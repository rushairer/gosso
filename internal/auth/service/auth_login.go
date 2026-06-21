package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/utility"

	"go.uber.org/zap"
)

// LoginByUsernamePassword login by username and password
func (s *AuthService) LoginByUsernamePassword(ctx context.Context, req *LoginCommand) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.loginAuditLogsSync(ctx, auditDomain.ActionLoginFailure, req.IP, nil,
				map[string]any{"username": req.Username},
				map[string]any{"ip": req.IP, "user_agent": req.UserAgent, "reason": safeAuditReason(err)},
			)
		}
	}()

	// Prevent brute-force attacks via extremely long inputs.
	// Capped at utility.MaxPasswordLength (72) to prevent excessive Argon2id resource usage.
	const maxUsernameLen = 254
	const maxPasswordLen = utility.MaxPasswordLength

	// 1. Check rate limit for login failures (keyed on IP + normalized username).
	// This is the SECOND layer of dual-layer rate limiting — the first layer is the
	// per-IP loginLimit middleware in the router. This service-level check adds
	// per-IP+username granularity to prevent targeted account enumeration.
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

	// 2. Find account and password credential in a single JOIN query.
	// This replaces the previous two sequential queries (FindAccountByUsername +
	// FindPasswordCredential) to eliminate one DB round-trip on the login hot path.
	account, cred, err := s.accountSvc.FindByUsernameWithPasswordCredential(ctx, normalizedUsername)
	if err != nil {
		// Distinguish "account not found" from "credential not found" for the
		// dummy-hash path — both produce ErrInvalidCredentials but trigger the
		// same timing side-channel mitigation.
		isAccountNotFound := errors.Is(err, accountRepo.ErrAccountNotFound)
		isCredentialNotFound := errors.Is(err, accountRepo.ErrCredentialNotFound)

		if isAccountNotFound || isCredentialNotFound {
			// Mitigate timing side-channel: perform a dummy Argon2id hash so the response
			// time is indistinguishable from "account found, wrong password."
			// The semaphore prevents an attacker from exhausting server resources by
			// sending many requests for non-existent usernames.
			if acquireErr := s.dummyHashSem.Acquire(ctx, 1); acquireErr == nil {
				defer s.dummyHashSem.Release(1)
				if _, hashErr := accountDomain.HashPassword(req.Password); hashErr != nil {
					s.logger.Debug("Dummy hash failed, falling back to sleep-based dummy work", zap.Error(hashErr))
					utility.DummyWorkWithContext(ctx)
				}
			}
			return nil, ErrInvalidCredentials
		}
		// Unexpected DB error — return service unavailable.
		return nil, ErrServiceUnavailable
	}

	// 3. Check account status
	if !account.IsActive() {
		// Mitigate timing side-channel: inactive accounts must perform the same
		// dummy work as the not-found path to prevent account existence enumeration.
		if acquireErr := s.dummyHashSem.Acquire(ctx, 1); acquireErr == nil {
			defer s.dummyHashSem.Release(1)
			if _, hashErr := accountDomain.HashPassword(req.Password); hashErr != nil {
				s.logger.Debug("Dummy hash failed, falling back to sleep-based dummy work", zap.Error(hashErr))
				utility.DummyWorkWithContext(ctx)
			}
		}
		return nil, ErrInvalidCredentials
	}

	// 4. Verify password
	if !cred.VerifyPassword(req.Password) {
		return nil, ErrInvalidCredentials
	}

	// 5. Check if MFA is required
	mfaResult, mfaErr := s.handleMFARequirement(ctx, account)
	if mfaResult != nil || mfaErr != nil {
		// Password was correct but MFA is required — do NOT clear rate limit yet.
		// The counter will be cleared after successful MFA verification.
		// IP-based counter is intentionally preserved to prevent brute force from the same IP.
		return mfaResult, mfaErr
	}

	// 6. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, req.IP, req.UserAgent)
	if err != nil {
		return nil, err
	}

	// 7. Update credential last used time
	cred.MarkUsed()
	if txErr := s.updateCredentialLastUsed(ctx, cred); txErr != nil {
		s.logger.Warn("Failed to update credential last_used_at", zap.Error(txErr))
	}

	s.logger.Info("Login successful",
		zap.String("account_id", utility.MaskOpaqueID(account.ID)),
		zap.String("session_id", utility.MaskOpaqueID(session.ID)))

	// Clear login failures count
	s.clearLoginRateLimits(ctx, req.IP, account.Username)

	// 8. Audit log
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
				zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.String("jti", utility.MaskOpaqueID(claims.ID)), zap.Error(bErr))
		}
		return nil, err
	}

	// 3. Find account BEFORE blacklisting the MFA token.
	// If the account lookup or active check fails transiently, the user can retry
	// MFA verification without losing their token.
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !account.IsActive() {
		return nil, ErrInvalidCredentials
	}

	// 4. Blacklist MFA token after successful verification and account validation
	// to prevent reuse before session creation. Fail-closed: if blacklisting fails,
	// reject the login to prevent potential MFA token reuse.
	if err := s.blacklistMFAToken(ctx, claims); err != nil {
		s.logger.Error("Failed to blacklist MFA token after verification — rejecting login for safety",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.String("jti", utility.MaskOpaqueID(claims.ID)), zap.Error(err))
		return nil, ErrInvalidCredentials
	}

	// 5. Complete login (session, tokens, rate limit clear, audit)
	return s.completeLogin(ctx, account, ip, userAgent, auditDomain.ActionMFALoginSuccess, nil, true)
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

	// 2. Per-account rate limiting (prevents brute-force on passkey MFA)
	if err := s.checkMFAAccountRateLimit(ctx, accountID); err != nil {
		return nil, err
	}

	// 3. Verify passkey MFA flag (set by CompleteMFALogin in the passkey controller)
	if err := s.verifyPasskeyMFAFlag(ctx, claims.ID, accountID); err != nil {
		return nil, err
	}

	// 4. Find account before blacklisting MFA token.
	// If the account lookup fails, the MFA token remains valid so the user can retry
	// without restarting the entire passkey flow.
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !account.IsActive() {
		return nil, ErrInvalidCredentials
	}

	// 5. Blacklist MFA token to prevent reuse
	if err := s.blacklistMFAToken(ctx, claims); err != nil {
		return nil, err
	}

	// 6. Complete login (session, tokens, rate limit clear, audit)
	return s.completeLogin(ctx, account, ip, userAgent, auditDomain.ActionMFALoginSuccess, nil, true)
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
		map[string]any{"method": "passkey"}, false)
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
		utility.MarshalJSONOrEmpty(map[string]any{"session_id": sessionID}),
		utility.MarshalJSONOrEmpty(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
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
	const maxIterations = 1000
	for i := 0; i < maxIterations; i++ {
		// Respect context cancellation (e.g., graceful shutdown).
		if ctx.Err() != nil {
			return firstErr
		}
		keys, nextCursor, err := s.redis.ScanKeys(ctx, cursor, pattern, 100)
		if err != nil {
			s.logger.Warn("Failed to scan login rate limit keys during cleanup",
				zap.String("username", utility.MaskEmail(username)), zap.Error(err))
			return fmt.Errorf("scan rate limit keys: %w", err)
		}
		if len(keys) > 0 {
			if delErr := s.redis.Del(ctx, keys...); delErr != nil {
				s.logger.Warn("Failed to delete login rate limit keys",
					zap.Int("count", len(keys)),
					zap.String("pattern_masked", utility.MaskRateLimitKey(pattern)),
					zap.Error(delErr))
				if firstErr == nil {
					firstErr = fmt.Errorf("delete rate limit keys: %w", delErr)
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
