package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/utility"

	"go.uber.org/zap"
)

const (
	loginRateLimitWindow = 15 * time.Minute
	loginMaxAttempts     = 5
)

// LoginByUsernamePassword login by username and password
func (s *AuthService) LoginByUsernamePassword(ctx context.Context, req *LoginRequest) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.loginAuditLogs(ctx, auditDomain.ActionLoginFailure, req.Username, nil,
				map[string]any{"username": req.Username},
				map[string]any{"ip": req.IP, "user_agent": req.UserAgent, "reason": err.Error()},
			)
		}
	}()

	// 0. Check rate limit for login failures (keyed on IP + normalized username)
	normalizedUsername := strings.ToLower(req.Username)
	attemptsKey := fmt.Sprintf("login_attempts:%s:%s", req.IP, normalizedUsername)
	count, incrErr := s.redis.IncrWithExpiry(ctx, attemptsKey, loginRateLimitWindow)
	if incrErr != nil {
		s.logger.Warn("Failed to check login rate limit, proceeding anyway", zap.Error(incrErr))
	} else if count > loginMaxAttempts {
		return nil, ErrAccountLocked
	}

	// 1. Find account
	account, err := s.accountSvc.FindAccountByUsername(ctx, req.Username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 2. Check account status
	if account.Status != accountDomain.AccountStatusActive {
		return nil, ErrInvalidCredentials
	}

	// 3. Find password credential
	cred, err := s.credentialRepo.FindPasswordCredential(ctx, account.ID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 4. Verify password
	if !cred.VerifyPassword(req.Password) {
		return nil, ErrInvalidCredentials
	}

	// 5. Check if MFA is required
	mfaResult, mfaErr := s.handleMFARequirement(ctx, account)
	if mfaResult != nil || mfaErr != nil {
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
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID.String()))

	// Clear login failures count
	_ = s.redis.Del(ctx, attemptsKey)

	// 8. Audit log
	accountUUID, err := uuid.Parse(account.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid account id: %w", err)
	}
	s.loginAuditLogs(ctx, auditDomain.ActionLoginSuccess, req.Username, &accountUUID,
		map[string]any{"account_id": account.ID, "session_id": session.ID.String()},
		map[string]any{"ip": req.IP, "user_agent": req.UserAgent},
	)

	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		RequiresMFA:  false,
	}, nil
}

// VerifyMFALogin completes login after MFA verification
func (s *AuthService) VerifyMFALogin(ctx context.Context, mfaToken, mfaCode, mfaType, ip, userAgent string) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.loginAuditLogs(ctx, auditDomain.ActionMFALoginFailure, "", nil,
				map[string]any{"reason": err.Error()},
				map[string]any{"ip": ip, "user_agent": userAgent},
			)
		}
	}()

	// 1. Verify MFA token
	claims, err := s.tokenSvc.ValidateAccessToken(mfaToken)
	if err != nil {
		return nil, ErrInvalidMFAToken
	}
	if claims.Scope != "mfa" {
		return nil, ErrInvalidMFATokenScope
	}
	accountID := claims.AccountID

	// 2. Verify based on MFA type
	if err := s.verifyMFACode(ctx, mfaType, accountID, mfaCode); err != nil {
		return nil, err
	}

	// 3. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAccountNotFound, err)
	}

	// 4. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("MFA login successful", zap.String("account_id", account.ID))

	// 5. Audit log
	if accountUUID, parseErr := uuid.Parse(account.ID); parseErr == nil {
		s.loginAuditLogs(ctx, auditDomain.ActionMFALoginSuccess, "", &accountUUID,
			map[string]any{"account_id": account.ID, "session_id": session.ID.String()},
			map[string]any{"ip": ip, "user_agent": userAgent},
		)
	}

	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		RequiresMFA:  false,
	}, nil
}

// CompletePasskeyMFALogin completes MFA login directly after passkey verification,
// avoiding the extra round-trip to /mfa/verify. The MFA token is validated here.
func (s *AuthService) CompletePasskeyMFALogin(ctx context.Context, mfaToken, ip, userAgent string) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.loginAuditLogs(ctx, auditDomain.ActionMFALoginFailure, "", nil,
				map[string]any{"reason": err.Error()},
				map[string]any{"ip": ip, "user_agent": userAgent},
			)
		}
	}()

	// 1. Validate MFA token
	claims, err := s.tokenSvc.ValidateAccessToken(mfaToken)
	if err != nil {
		return nil, ErrInvalidMFAToken
	}
	if claims.Scope != "mfa" {
		return nil, ErrInvalidMFATokenScope
	}
	accountID := claims.AccountID

	// 2. Verify passkey MFA flag (set by CompleteMFALogin in the passkey controller)
	passkeyKey := fmt.Sprintf("webauthn:mfa_verified:%s", accountID)
	verified, verr := s.redis.Get(ctx, passkeyKey)
	if verr != nil || verified != "1" {
		return nil, ErrPasskeyNotVerified
	}
	_ = s.redis.Del(ctx, passkeyKey)

	// 3. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAccountNotFound, err)
	}

	// 4. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Passkey MFA login successful", zap.String("account_id", account.ID))

	// 5. Audit log
	if accountUUID, parseErr := uuid.Parse(account.ID); parseErr == nil {
		s.loginAuditLogs(ctx, auditDomain.ActionMFALoginSuccess, "", &accountUUID,
			map[string]any{"account_id": account.ID, "session_id": session.ID.String()},
			map[string]any{"ip": ip, "user_agent": userAgent},
		)
	}

	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		RequiresMFA:  false,
	}, nil
}

// LoginByPasskey login directly after passkey verification (skipping password check)
func (s *AuthService) LoginByPasskey(ctx context.Context, accountID, ip, userAgent string) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.loginAuditLogs(ctx, auditDomain.ActionLoginFailure, accountID, nil,
				map[string]any{"method": "passkey", "account_id": accountID},
				map[string]any{"ip": ip, "user_agent": userAgent, "reason": err.Error()},
			)
		}
	}()

	// 1. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrAccountNotFound
	}

	// 2. Check account status
	if account.Status != accountDomain.AccountStatusActive {
		return nil, ErrInvalidCredentials
	}

	// 3. Check if MFA is required
	if result, err := s.handleMFARequirement(ctx, account); result != nil || err != nil {
		return result, err
	}

	// 4. Create session and tokens
	session, accessToken, refreshToken, err := s.createSessionAndTokens(ctx, account, ip, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Passkey login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID.String()))

	// 5. Audit log
	if accountUUID, parseErr := uuid.Parse(account.ID); parseErr == nil {
		s.loginAuditLogs(ctx, auditDomain.ActionLoginSuccess, accountID, &accountUUID,
			map[string]any{"method": "passkey", "account_id": account.ID, "session_id": session.ID.String()},
			map[string]any{"ip": ip, "user_agent": userAgent},
		)
	}

	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
		RequiresMFA:  false,
	}, nil
}

// Logout deletes session and revokes tokens
func (s *AuthService) Logout(ctx context.Context, accountID, sessionID string, accessTokenJTI string, tokenExpiresAt time.Time) error {
	// 1. Revoke session (removes from both session store and account index)
	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}

	if err := s.sessionSvc.RevokeSession(ctx, accountID, parsedSessionID); err != nil {
		s.logger.Warn("Failed to revoke session during logout", zap.Error(err))
	}

	// 2. Revoke refresh tokens for this session
	if accessTokenJTI != "" {
		if err := s.tokenSvc.RevokeAllForSession(ctx, sessionID); err != nil {
			s.logger.Warn("Failed to revoke refresh tokens", zap.Error(err))
		}
	}

	// 3. Blacklist the access token so it cannot be used after logout
	if accessTokenJTI != "" {
		if err := s.tokenSvc.RevokeAccessToken(ctx, accessTokenJTI, tokenExpiresAt); err != nil {
			s.logger.Warn("Failed to blacklist access token", zap.Error(err))
		}
	}

	// 4. Audit log
	var acctID *uuid.UUID
	if accountID != "" {
		id, err := uuid.Parse(accountID)
		if err != nil {
			s.logger.Warn("Invalid account ID in logout", zap.String("account_id", accountID), zap.Error(err))
		} else {
			acctID = &id
		}
	}
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionLogout,
		audit.IPFromContext(ctx),
		acctID,
		utility.MustMarshalJSON(map[string]any{"session_id": sessionID}),
		utility.MustMarshalJSON(map[string]any{"ip": audit.IPFromContext(ctx), "user_agent": audit.UserAgentFromContext(ctx)}),
	))

	s.logger.Info("Logout successful", zap.String("session_id", sessionID))
	return nil
}

// handleMFARequirement checks if MFA is required for the account and returns an MFA result if so.
// Returns nil, nil if MFA is not required.
func (s *AuthService) handleMFARequirement(ctx context.Context, account *accountDomain.Account) (*LoginResult, error) {
	mfaEnabled, _ := s.mfaSvc.IsMFAEnabled(ctx, account.ID)
	if !mfaEnabled {
		return nil, nil
	}

	mfaToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		AccountID: account.ID,
		Scope:     "mfa",
	})
	if err != nil {
		return nil, fmt.Errorf("generate mfa token: %w", err)
	}
	return &LoginResult{
		Account:     account,
		RequiresMFA: true,
		AccessToken: mfaToken,
		MFATypes:    s.mfaSvc.GetMFATypes(ctx, account.ID),
	}, nil
}

// verifyMFACode verifies MFA code based on the MFA type.
func (s *AuthService) verifyMFACode(ctx context.Context, mfaType, accountID, mfaCode string) error {
	switch mfaType {
	case "passkey":
		if s.passkeySvc == nil {
			return ErrPasskeyNotAvailable
		}
		passkeyKey := fmt.Sprintf("webauthn:mfa_verified:%s", accountID)
		verified, verr := s.redis.Get(ctx, passkeyKey)
		if verr != nil || verified != "1" {
			return ErrPasskeyNotVerified
		}
		_ = s.redis.Del(ctx, passkeyKey)
	default:
		// TOTP / backup code
		valid, verr := s.mfaSvc.VerifyTOTP(ctx, accountID, mfaCode)
		if verr != nil || !valid {
			valid, verr = s.mfaSvc.VerifyBackupCode(ctx, accountID, mfaCode)
			if verr != nil || !valid {
				return ErrInvalidMFACode
			}
		}
	}
	return nil
}
