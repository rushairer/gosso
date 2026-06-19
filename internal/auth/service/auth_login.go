package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/utility"

	"go.uber.org/zap"
)

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

	// 1. Check rate limit for login failures (keyed on IP + normalized username).
	// Fail-closed: if Redis is unavailable, deny login to prevent brute-force attacks.
	// Rate limit is checked BEFORE input validation so that empty/invalid credentials
	// are still counted — otherwise an attacker can probe with unlimited empty requests.
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

	// Validate input lengths AFTER rate limit check to prevent unlimited empty-credential probing.
	if len(req.Username) > maxUsernameLen || len(req.Password) > maxPasswordLen || req.Username == "" || req.Password == "" {
		return nil, ErrInvalidCredentials
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
		zap.String("account_id", utility.MaskOpaqueID(account.ID)),
		zap.String("session_id", utility.MaskOpaqueID(session.ID)))

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
	claims, err := s.ValidateMFAToken(ctx, mfaToken)
	if err != nil {
		return nil, err
	}
	accountID := claims.AccountID
	mfaAccountID = &accountID

	// Prevent brute-force against MFA codes per account (not just per IP).
	if err := s.checkMFAAccountRateLimit(ctx, accountID); err != nil {
		return nil, err
	}

	// 2. Verify based on MFA type
	if err := s.verifyMFACode(ctx, mfaType, accountID, mfaCode, claims.ID); err != nil {
		// Blacklist MFA token on failure to prevent brute-force replay.
		if bErr := s.blacklistMFAToken(ctx, claims); bErr != nil {
			s.logger.Error("Failed to blacklist MFA token after failed verification",
				zap.String("account_id", accountID), zap.String("jti", utility.MaskOpaqueID(claims.ID)), zap.Error(bErr))
		}
		return nil, err
	}

	// 3. Blacklist MFA token immediately after successful verification to prevent reuse
	// before session creation. This closes the race window between MFA verification and
	// the eventual function return that would fire a deferred blacklist.
	if err := s.blacklistMFAToken(ctx, claims); err != nil {
		s.logger.Error("Failed to blacklist MFA token after verification",
			zap.String("account_id", accountID), zap.String("jti", utility.MaskOpaqueID(claims.ID)), zap.Error(err))
	}

	// 4. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !account.IsActive() {
		return nil, ErrInvalidCredentials
	}

	// 5. Complete login (session, tokens, rate limit clear, audit)
	return s.completeLogin(ctx, account, ip, userAgent, auditDomain.ActionMFALoginSuccess, nil)
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
	claims, err := s.ValidateMFAToken(ctx, mfaToken)
	if err != nil {
		return nil, err
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

	// 5. Complete login (session, tokens, rate limit clear, audit)
	return s.completeLogin(ctx, account, ip, userAgent, auditDomain.ActionMFALoginSuccess, nil)
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
		// Mitigate timing side-channel: inactive accounts must perform the same
		// dummy work as the not-found path to prevent account existence enumeration.
		// Passkey login has no password, so use sleep-based dummy work instead of Argon2id.
		utility.DummyWorkWithContext(ctx)
		return nil, ErrInvalidCredentials
	}

	// 3. Check if MFA is required
	mfaResult, mfaErr := s.handleMFARequirement(ctx, account)
	if mfaResult != nil || mfaErr != nil {
		return mfaResult, mfaErr
	}

	// 4. Complete login (session, tokens, rate limit clear, audit)
	return s.completeLogin(ctx, account, ip, userAgent, auditDomain.ActionLoginSuccess,
		map[string]any{"method": "passkey"})
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

	s.logger.Info("Logout successful", zap.String("session_id", utility.MaskOpaqueID(sessionID)))
	return nil
}

// ClearLoginRateLimitsByUsername clears all per-user+IP login rate-limit counters
// for the given username across all IPs. Used after password reset to unblock
// accounts that were locked by brute-force attacks.
// Uses SCAN with pattern matching since the IP component is unknown.
// Returns the first error encountered, if any.
func (s *AuthService) ClearLoginRateLimitsByUsername(ctx context.Context, username string) error {
	pattern := fmt.Sprintf("login_attempts:*:%s", strings.ToLower(username))
	cursor := uint64(0)
	var firstErr error
	for {
		keys, nextCursor, err := s.redis.ScanKeys(ctx, cursor, pattern, 100)
		if err != nil {
			s.logger.Warn("Failed to scan login rate limit keys during cleanup",
				zap.String("username", utility.MaskEmail(username)), zap.Error(err))
			return fmt.Errorf("scan rate limit keys: %w", err)
		}
		for _, key := range keys {
			if delErr := s.redis.Del(ctx, key); delErr != nil {
				s.logger.Warn("Failed to delete login rate limit key", zap.String("key", key), zap.Error(delErr))
				if firstErr == nil {
					firstErr = fmt.Errorf("delete rate limit key %s: %w", key, delErr)
				}
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return firstErr
}
