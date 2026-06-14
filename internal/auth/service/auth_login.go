package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"

	"go.uber.org/zap"
)

// safeAuditReason maps errors to safe generic messages for audit logs,
// preventing internal details (database errors, stack traces) from being persisted.
func safeAuditReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return "invalid_credentials"
	case errors.Is(err, ErrAccountLocked):
		return "account_locked"
	case errors.Is(err, ErrIPLocked):
		return "ip_rate_limited"
	case errors.Is(err, accountService.ErrAccountNotActive):
		return "account_inactive"
	case errors.Is(err, ErrInvalidMFACode):
		return "invalid_mfa_code"
	case errors.Is(err, ErrInvalidMFAToken), errors.Is(err, ErrInvalidMFATokenScope):
		return "invalid_mfa_token"
	case errors.Is(err, accountRepo.ErrAccountNotFound):
		return "account_not_found"
	default:
		return "internal_error"
	}
}

// buildLoginResult constructs a successful LoginResult from a session, access token, and refresh token.
func buildLoginResult(account *accountDomain.Account, session *sessionDomain.Session, accessToken string, refreshToken *tokenDomain.RefreshToken) *LoginResult {
	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		RequiresMFA:  false,
	}
}

// buildMFAResult constructs a LoginResult that signals MFA is required.
func buildMFAResult(account *accountDomain.Account, mfaToken string, mfaTypes []string) *LoginResult {
	return &LoginResult{
		Account:     account,
		RequiresMFA: true,
		AccessToken: mfaToken,
		MFATypes:    mfaTypes,
	}
}

// LoginByUsernamePassword login by username and password
func (s *AuthService) LoginByUsernamePassword(ctx context.Context, req *LoginRequest) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.loginAuditLogsSync(ctx, auditDomain.ActionLoginFailure, req.IP, nil,
				map[string]any{"username": req.Username},
				map[string]any{"ip": req.IP, "user_agent": req.UserAgent, "reason": safeAuditReason(err)},
			)
		}
	}()

	// Prevent brute-force attacks via extremely long inputs.
	// Argon2id allows longer passwords than bcrypt, but we still cap it at utility.MaxPasswordLength.
	const maxUsernameLen = 254
	const maxPasswordLen = utility.MaxPasswordLength
	if len(req.Username) > maxUsernameLen || len(req.Password) > maxPasswordLen || req.Username == "" || req.Password == "" {
		return nil, ErrInvalidCredentials
	}

	// 1. Check rate limit for login failures (keyed on IP + normalized username).
	// Fail-closed: if Redis is unavailable, deny login to prevent brute-force attacks.
	normalizedUsername := strings.ToLower(req.Username)
	normalizedIP := utility.NormalizeIP(req.IP)
	attemptsKey := fmt.Sprintf("login_attempts:%s:%s", normalizedIP, normalizedUsername)
	count, incrErr := s.redis.CheckAndIncr(ctx, attemptsKey, s.loginMaxAttempts, s.loginRateLimitWindow)
	if incrErr != nil {
		s.logger.Error("Failed to check login rate limit, denying login", zap.Error(incrErr))
		return nil, ErrServiceUnavailable
	}
	if count >= int64(s.loginMaxAttempts) {
		return nil, ErrAccountLocked
	}

	// Check overall IP-level rate limit to prevent username enumeration
	if err := s.checkIPRateLimit(ctx, req.IP); err != nil {
		return nil, err
	}

	// 2. Find account
	account, err := s.accountSvc.FindAccountByUsername(ctx, normalizedUsername)
	if err != nil {
		// Mitigate timing side-channel: perform a dummy Argon2id hash so the response
		// time is indistinguishable from "account found, wrong password."
		_, _ = accountDomain.HashPassword(req.Password)
		return nil, ErrInvalidCredentials
	}

	// 3. Check account status
	if !account.IsActive() {
		// Mitigate timing side-channel: inactive accounts must perform the same
		// dummy work as the not-found path to prevent account existence enumeration.
		_, _ = accountDomain.HashPassword(req.Password)
		return nil, ErrInvalidCredentials
	}

	// 4. Find password credential
	cred, err := s.credentialRepo.FindPasswordCredential(ctx, account.ID)
	if err != nil {
		// Mitigate timing side-channel: passkey-only accounts (no password credential)
		// must perform dummy work to prevent leaking account type via response timing.
		_, _ = accountDomain.HashPassword(req.Password)
		return nil, ErrInvalidCredentials
	}

	// 5. Verify password
	if !cred.VerifyPassword(req.Password) {
		return nil, ErrInvalidCredentials
	}

	// 6. Check if MFA is required
	mfaResult, mfaErr := s.handleMFARequirement(ctx, account)
	if mfaResult != nil || mfaErr != nil {
		// Password was correct but MFA is required — do NOT clear rate limit yet.
		// The counter will be cleared after successful MFA verification.
		// IP-based counter is intentionally preserved to prevent brute force from the same IP.
		return mfaResult, mfaErr
	}

	// 7. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, req.IP, req.UserAgent)
	if err != nil {
		return nil, err
	}

	// 8. Update credential last used time
	cred.MarkUsed()
	if txErr := s.updateCredentialLastUsed(ctx, cred); txErr != nil {
		s.logger.Warn("Failed to update credential last_used_at", zap.Error(txErr))
	}

	s.logger.Info("Login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID))

	// Clear login failures count
	s.clearLoginRateLimits(ctx, req.IP, account.Username)

	// 9. Audit log
	s.loginAuditLogs(ctx, auditDomain.ActionLoginSuccess, req.IP, &account.ID,
		map[string]any{"account_id": account.ID, "session_id": session.ID},
		map[string]any{"ip": req.IP, "user_agent": req.UserAgent},
	)

	return buildLoginResult(account, session, accessToken, refreshToken), nil
}

// VerifyMFALogin completes login after MFA verification
func (s *AuthService) VerifyMFALogin(ctx context.Context, mfaToken, mfaCode, mfaType, ip, userAgent string) (result *LoginResult, err error) {
	// Captured after MFA token validation; used in failure audit logs.
	var mfaAccountID *string
	defer func() {
		if err != nil {
			s.loginAuditLogsSync(ctx, auditDomain.ActionMFALoginFailure, ip, mfaAccountID,
				map[string]any{"reason": safeAuditReason(err)},
				map[string]any{"ip": ip, "user_agent": userAgent},
			)
		}
	}()

	// Prevent brute-force against MFA codes (TOTP/backup code).
	if err := s.checkIPRateLimit(ctx, ip); err != nil {
		return nil, err
	}

	// 1. Verify MFA token
	claims, err := s.tokenSvc.ValidateAccessTokenWithContext(ctx, mfaToken)
	if err != nil {
		return nil, ErrInvalidMFAToken
	}
	if claims.Scope != ScopeMFA {
		return nil, ErrInvalidMFATokenScope
	}
	accountID := claims.AccountID
	mfaAccountID = &accountID

	// 2. Blacklist MFA token immediately after validation to prevent reuse,
	// regardless of whether the MFA code verification succeeds or fails.
	defer func() {
		if err := s.blacklistMFAToken(ctx, claims); err != nil {
			s.logger.Error("Failed to blacklist MFA token after verification attempt",
				zap.String("account_id", accountID), zap.String("jti", claims.ID), zap.Error(err))
		}
	}()

	// 3. Verify based on MFA type
	if err := s.verifyMFACode(ctx, mfaType, accountID, mfaCode, claims.ID); err != nil {
		return nil, err
	}

	// 4. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !account.IsActive() {
		return nil, ErrInvalidCredentials
	}

	// 5. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("MFA login successful", zap.String("account_id", account.ID))

	// Clear login rate limit counters on successful MFA verification
	s.clearLoginRateLimits(ctx, ip, account.Username)

	// 6. Audit log
	s.loginAuditLogs(ctx, auditDomain.ActionMFALoginSuccess, ip, &account.ID,
		map[string]any{"account_id": account.ID, "session_id": session.ID},
		map[string]any{"ip": ip, "user_agent": userAgent},
	)

	return buildLoginResult(account, session, accessToken, refreshToken), nil
}

// CompletePasskeyMFALogin completes MFA login directly after passkey verification,
// avoiding the extra round-trip to /mfa/verify. The MFA token is validated here.
func (s *AuthService) CompletePasskeyMFALogin(ctx context.Context, mfaToken, ip, userAgent string) (result *LoginResult, err error) {
	// Captured after MFA token validation; used in failure audit logs.
	var mfaAccountID *string
	defer func() {
		if err != nil {
			s.loginAuditLogsSync(ctx, auditDomain.ActionMFALoginFailure, ip, mfaAccountID,
				map[string]any{"reason": safeAuditReason(err)},
				map[string]any{"ip": ip, "user_agent": userAgent},
			)
		}
	}()

	// IP-level rate limiting is handled by the passkeyRateLimit middleware.

	// 1. Validate MFA token
	claims, err := s.tokenSvc.ValidateAccessTokenWithContext(ctx, mfaToken)
	if err != nil {
		return nil, ErrInvalidMFAToken
	}
	if claims.Scope != ScopeMFA {
		return nil, ErrInvalidMFATokenScope
	}
	accountID := claims.AccountID
	mfaAccountID = &accountID

	// 2. Verify passkey MFA flag (set by CompleteMFALogin in the passkey controller)
	if err := s.verifyPasskeyMFAFlag(ctx, claims.ID, accountID); err != nil {
		return nil, err
	}

	// 3. Blacklist MFA token to prevent reuse
	if err := s.blacklistMFAToken(ctx, claims); err != nil {
		return nil, err
	}

	// 4. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !account.IsActive() {
		return nil, ErrInvalidCredentials
	}

	// 5. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Passkey MFA login successful", zap.String("account_id", account.ID))

	// Clear login rate limit counters on successful MFA verification
	s.clearLoginRateLimits(ctx, ip, account.Username)

	// 6. Audit log
	s.loginAuditLogs(ctx, auditDomain.ActionMFALoginSuccess, ip, &account.ID,
		map[string]any{"account_id": account.ID, "session_id": session.ID},
		map[string]any{"ip": ip, "user_agent": userAgent},
	)

	return buildLoginResult(account, session, accessToken, refreshToken), nil
}

// LoginByPasskey login directly after passkey verification (skipping password check)
func (s *AuthService) LoginByPasskey(ctx context.Context, accountID, ip, userAgent string) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.loginAuditLogsSync(ctx, auditDomain.ActionLoginFailure, ip, nil,
				map[string]any{"method": "passkey", "account_id": accountID},
				map[string]any{"ip": ip, "user_agent": userAgent, "reason": safeAuditReason(err)},
			)
		}
	}()

	// IP-level rate limiting is handled by the passkeyRateLimit middleware.
	// Adding a service-level check here would double-count each attempt.

	// 1. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 2. Check account status
	if !account.IsActive() {
		return nil, ErrInvalidCredentials
	}

	// 3. Check if MFA is required
	mfaResult, mfaErr := s.handleMFARequirement(ctx, account)
	if mfaResult != nil || mfaErr != nil {
		return mfaResult, mfaErr
	}

	// 4. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Passkey login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID))

	// 5. Audit log
	s.loginAuditLogs(ctx, auditDomain.ActionLoginSuccess, ip, &account.ID,
		map[string]any{"method": "passkey", "account_id": account.ID, "session_id": session.ID},
		map[string]any{"ip": ip, "user_agent": userAgent},
	)

	// 6. Clear rate-limit counters on successful passkey login
	s.clearLoginRateLimits(ctx, ip, account.Username)

	return buildLoginResult(account, session, accessToken, refreshToken), nil
}

// Logout deletes session and revokes tokens
func (s *AuthService) Logout(ctx context.Context, accountID, sessionID string, accessTokenJTI string, tokenExpiresAt time.Time) error {
	var errs []error

	// 1. Revoke session (removes from both session store and account index)
	if err := s.sessionSvc.RevokeSession(ctx, accountID, sessionID); err != nil {
		s.logger.Warn("Failed to revoke session during logout", zap.Error(err))
		errs = append(errs, fmt.Errorf("revoke session: %w", err))
	}

	// 2. Revoke refresh tokens for this session (always, regardless of accessTokenJTI)
	if err := s.tokenSvc.RevokeAllForSession(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to revoke refresh tokens", zap.Error(err))
		errs = append(errs, fmt.Errorf("revoke refresh tokens: %w", err))
	}

	// 3. Blacklist the access token (best-effort: the token will expire naturally).
	// Failure here should not cause logout to fail, since session and refresh
	// tokens are already revoked above — the critical security state is achieved.
	if accessTokenJTI != "" {
		if err := s.tokenSvc.RevokeAccessToken(ctx, accessTokenJTI, tokenExpiresAt); err != nil {
			s.logger.Warn("Failed to blacklist access token (will expire naturally)", zap.Error(err))
		}
	}

	// 4. Audit log
	var acctID *string
	if accountID != "" {
		acctID = &accountID
	}
	auditService.AuditLog(ctx, s.auditor, s.logger, auditDomain.NewRecord(
		auditDomain.ActionLogout,
		audit.IPFromContext(ctx),
		acctID,
		utility.MustMarshalJSON(map[string]any{"session_id": sessionID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	s.logger.Info("Logout successful", zap.String("session_id", sessionID))
	return nil
}

// handleMFARequirement checks if MFA is required for the account and returns an MFA result if so.
// Returns nil, nil if MFA is not required.
// Fail-closed: if the MFA status check fails, login is denied rather than bypassed.
func (s *AuthService) handleMFARequirement(ctx context.Context, account *accountDomain.Account) (*LoginResult, error) {
	mfaEnabled, err := s.mfaSvc.IsMFAEnabled(ctx, account.ID)
	if err != nil {
		s.logger.Error("Failed to check MFA status, denying login", zap.String("account_id", account.ID), zap.Error(err))
		return nil, fmt.Errorf("check mfa status: %w", err)
	}
	if !mfaEnabled {
		return nil, nil
	}

	mfaToken, err := s.tokenSvc.GenerateShortLivedToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.mfaVerificationTTL)),
		},
		AccountID: account.ID,
		Scope:     ScopeMFA,
	})
	if err != nil {
		return nil, fmt.Errorf("generate mfa token: %w", err)
	}
	return buildMFAResult(account, mfaToken, s.mfaSvc.GetMFATypes(ctx, account.ID)), nil
}

// CheckMFA implements the MFAChecker interface for use by SocialLoginService.
func (s *AuthService) CheckMFA(ctx context.Context, account *accountDomain.Account) (*LoginResult, error) {
	return s.handleMFARequirement(ctx, account)
}

// blacklistMFAToken revokes an MFA token to prevent reuse after successful verification.
func (s *AuthService) blacklistMFAToken(ctx context.Context, claims *tokenDomain.AccessTokenClaims) error {
	if claims.ID == "" {
		return nil
	}
	if err := s.tokenSvc.RevokeAccessToken(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		return fmt.Errorf("blacklist mfa token: %w", err)
	}
	return nil
}

// verifyPasskeyMFAFlag checks and consumes the Redis flag set by the passkey controller
// after a successful WebAuthn ceremony. The flag is namespaced by the MFA token JTI to
// prevent concurrent login interference. Returns nil if verified, an error otherwise.
func (s *AuthService) verifyPasskeyMFAFlag(ctx context.Context, mfaTokenJTI, accountID string) error {
	passkeyKey := fmt.Sprintf("webauthn:mfa_verified:%s", mfaTokenJTI)
	verified, verr := s.redis.GetDel(ctx, passkeyKey)
	if verr != nil {
		s.logger.Error("Redis GetDel failed for passkey MFA verification",
			zap.Error(verr), zap.String("account_id", accountID))
		return fmt.Errorf("verify passkey mfa: %w", verr)
	}
	if verified != "1" {
		return ErrPasskeyNotVerified
	}
	return nil
}

// verifyMFACode verifies MFA code based on the MFA type.
func (s *AuthService) verifyMFACode(ctx context.Context, mfaType, accountID, mfaCode, mfaTokenJTI string) error {
	switch mfaType {
	case "passkey":
		if s.passkeySvc == nil {
			return ErrPasskeyNotAvailable
		}
		return s.verifyPasskeyMFAFlag(ctx, mfaTokenJTI, accountID)
	case "totp":
		// TOTP / backup code
		valid, verr := s.mfaSvc.VerifyTOTP(ctx, accountID, mfaCode)
		if verr != nil {
			return fmt.Errorf("totp verification error: %w", verr)
		}
		if valid {
			return nil
		}
		// TOTP code was invalid — try backup codes
		valid, berr := s.mfaSvc.VerifyBackupCode(ctx, accountID, mfaCode)
		if berr != nil {
			return fmt.Errorf("backup code verification error: %w", berr)
		}
		if !valid {
			return ErrInvalidMFACode
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedMFAType, mfaType)
	}
}

// checkIPRateLimit checks and increments the per-IP login rate limit.
// Returns ErrIPLocked if the limit is exceeded. Returns ErrServiceUnavailable
// if Redis is unavailable (fail-closed for rate limiting).
func (s *AuthService) checkIPRateLimit(ctx context.Context, ip string) error {
	normalizedIP := utility.NormalizeIP(ip)
	ipAttemptsKey := fmt.Sprintf("login_attempts_ip:%s", normalizedIP)
	ipCount, ipIncrErr := s.redis.CheckAndIncr(ctx, ipAttemptsKey, s.loginMaxAttemptsPerIP, s.loginRateLimitWindow)
	if ipIncrErr != nil {
		s.logger.Error("Failed to check IP login rate limit, denying login", zap.Error(ipIncrErr))
		return ErrServiceUnavailable
	}
	if ipCount >= int64(s.loginMaxAttemptsPerIP) {
		return ErrIPLocked
	}
	return nil
}

// clearLoginRateLimits removes per-user rate limit counters after successful login.
// Per-IP limits are intentionally preserved to prevent abuse from distributed attacks
// that use many accounts from the same IP.
func (s *AuthService) clearLoginRateLimits(ctx context.Context, ip string, username *string) {
	if username != nil {
		normalizedIP := utility.NormalizeIP(ip)
		key := fmt.Sprintf("login_attempts:%s:%s", normalizedIP, strings.ToLower(*username))
		if err := s.redis.Del(ctx, key); err != nil {
			s.logger.Warn("Failed to clear rate limit counter after successful login", zap.String("key", key), zap.Error(err))
		}
	}
}

// ClearLoginRateLimitsByUsername clears all per-user+IP login rate-limit counters
// for the given username across all IPs. Used after password reset to unblock
// accounts that were locked by brute-force attacks.
// Uses SCAN with pattern matching since the IP component is unknown.
func (s *AuthService) ClearLoginRateLimitsByUsername(ctx context.Context, username string) {
	pattern := fmt.Sprintf("login_attempts:*:%s", strings.ToLower(username))
	cursor := uint64(0)
	for {
		keys, nextCursor, err := s.redis.ScanKeys(ctx, cursor, pattern, 100)
		if err != nil {
			s.logger.Warn("Failed to scan login rate limit keys during cleanup",
				zap.String("username", utility.MaskEmail(username)), zap.Error(err))
			return
		}
		for _, key := range keys {
			if delErr := s.redis.Del(ctx, key); delErr != nil {
				s.logger.Warn("Failed to delete login rate limit key", zap.String("key", key), zap.Error(delErr))
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}
