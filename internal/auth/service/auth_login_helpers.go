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

// handleMFARequirement checks if MFA is required for the account and returns an MFA result if so.
// Returns nil, nil if MFA is not required.
// Fail-closed: if the MFA status check fails, login is denied rather than bypassed.
func (s *AuthService) handleMFARequirement(ctx context.Context, account *accountDomain.Account) (*LoginResult, error) {
	mfaEnabled, err := s.mfaSvc.IsMFAEnabled(ctx, account.ID)
	if err != nil {
		s.logger.Error("Failed to check MFA status, denying login", zap.String("account_id", account.ID), zap.Error(err))
		return nil, ErrServiceUnavailable
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

// checkMFAAccountRateLimit enforces per-account rate limiting on MFA code verification attempts.
// This prevents brute-force attacks on TOTP codes even with a valid MFA token.
// Fail-closed: if Redis is unavailable, deny the attempt.
func (s *AuthService) checkMFAAccountRateLimit(ctx context.Context, accountID string) error {
	key := fmt.Sprintf("mfa_attempts:%s", accountID)
	count, incrErr := s.redis.CheckAndIncr(ctx, key, mfaAccountMaxAttempts, mfaAccountRateLimitWindow)
	if incrErr != nil {
		s.logger.Error("Failed to check MFA account rate limit, denying attempt", zap.Error(incrErr))
		return ErrServiceUnavailable
	}
	if count >= int64(mfaAccountMaxAttempts) {
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

// completeLogin performs the common post-authentication steps: create session and tokens,
// clear rate limits, and write a success audit log. Returns the login result.
func (s *AuthService) completeLogin(ctx context.Context, account *accountDomain.Account, ip, userAgent, action string, extraDetail map[string]any) (*LoginResult, error) {
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", utility.MaskOpaqueID(session.ID)))

	s.clearLoginRateLimits(ctx, ip, account.Username)

	detail := map[string]any{"account_id": account.ID, "session_id": session.ID}
	for k, v := range extraDetail {
		detail[k] = v
	}
	s.loginAuditLogs(ctx, action, ip, &account.ID,
		detail,
		map[string]any{"ip": ip, "user_agent": userAgent},
	)

	return buildLoginResult(account, session, accessToken, refreshToken), nil
}
