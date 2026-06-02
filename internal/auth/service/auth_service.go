package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/audit"
	auditDomain "github.com/rushairer/gosso/internal/audit/domain"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/cache"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/utility"
)

// LoginRequest login request
type LoginRequest struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}

// LoginResult login result
type LoginResult struct {
	Account      *accountDomain.Account
	Session      *sessionDomain.Session
	AccessToken  string
	RefreshToken string
	RequiresMFA  bool
	MFATypes     []string `json:"mfa_types,omitempty"`
}

// RefreshResult refresh token result
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
}

// AuthService authentication orchestration service
type AuthService struct {
	db             *sql.DB
	accountSvc     accountService.AccountService
	sessionSvc     *sessionService.SessionService
	tokenSvc       *tokenService.TokenService
	credentialRepo accountRepo.CredentialRepository
	roleRepo       accountRepo.RoleRepository
	redis          *cache.RedisClient
	mfaSvc         *MFAService
	passkeySvc     *PasskeyService
	auditor        *auditService.Auditor
	logger         *zap.Logger
}

// NewAuthService creates a new auth service instance
func NewAuthService(
	db *sql.DB,
	accountSvc accountService.AccountService,
	sessionSvc *sessionService.SessionService,
	tokenSvc *tokenService.TokenService,
	credentialRepo accountRepo.CredentialRepository,
	roleRepo accountRepo.RoleRepository,
	redis *cache.RedisClient,
	logger *zap.Logger,
	auditor *auditService.Auditor,
	mfaSvc *MFAService,
	passkeySvc *PasskeyService,
) *AuthService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &AuthService{
		db:             db,
		accountSvc:     accountSvc,
		sessionSvc:     sessionSvc,
		tokenSvc:       tokenSvc,
		credentialRepo: credentialRepo,
		roleRepo:       roleRepo,
		redis:          redis,
		mfaSvc:         mfaSvc,
		auditor:        auditor,
		logger:         logger,
		passkeySvc:     passkeySvc,
	}
}

// LoginByUsernamePassword login by username and password
func (s *AuthService) LoginByUsernamePassword(ctx context.Context, req *LoginRequest) (result *LoginResult, err error) {
	defer func() {
		if err != nil {
			s.auditLog(ctx, auditDomain.NewRecord(
				auditDomain.ActionLoginFailure,
				req.Username,
				nil,
				utility.MustMarshalJSON(map[string]any{"username": req.Username}),
				utility.MustMarshalJSON(map[string]any{"ip": req.IP, "user_agent": req.UserAgent, "reason": err.Error()}),
			))
		}
	}()

	// 0. Check rate limit for login failures
	attemptsKey := fmt.Sprintf("login_attempts:%s", req.Username)
	count, err := s.redis.IncrWithExpiry(ctx, attemptsKey, 15*time.Minute)
	if err == nil && count > 5 {
		return nil, ErrAccountLocked
	}

	// 1. Find account
	account, err := s.accountSvc.FindAccountByUsername(ctx, req.Username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 2. Check account status
	if account.Status != accountDomain.AccountStatusActive {
		return nil, ErrAccountNotActive
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

	// 4.5 Check if MFA is required
	mfaEnabled, _ := s.mfaSvc.IsMFAEnabled(ctx, account.ID)
	if mfaEnabled {
		mfaToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
			AccountID: account.ID,
			Scope:     "mfa",
		})
		if err != nil {
			return nil, fmt.Errorf("generate mfa token: %w", err)
		}
		return &LoginResult{
			Account:     account,
			RequiresMFA: true,
			AccessToken: mfaToken, // short-term MFA session token
			MFATypes:    s.mfaSvc.GetMFATypes(ctx, account.ID),
		}, nil
	}

	// 5. Create session
	now := time.Now()
	session := &sessionDomain.Session{
		ID:           uuid.New(),
		AccountID:    uuid.MustParse(account.ID),
		IP:           req.IP,
		UserAgent:    req.UserAgent,
		CreatedAt:    now,
		LastActiveAt: now,
	}
	if account.Username != nil {
		session.Username = *account.Username
	}

	if err := s.sessionSvc.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// 5.5 Enforce concurrent session limit
	s.sessionSvc.EnforceSessionLimit(ctx, account.ID)

	// 6. Get roles and permissions
	roles, err := s.roleRepo.FindRolesByAccountID(ctx, account.ID)
	if err != nil {
		s.logger.Warn("Failed to fetch roles for token", zap.Error(err), zap.String("account_id", account.ID))
		roles = nil
	}

	var roleNames []string
	var allPermissions []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		allPermissions = append(allPermissions, role.Permissions...)
	}

	// 7. Generate Access Token
	accessToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID:   account.ID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   session.ID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 8. Generate Refresh Token
	refreshToken, err := s.tokenSvc.GenerateRefreshToken(ctx, account.ID, "", session.ID.String(), "")
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// 9. Update credential last used time
	cred.MarkUsed()
	if txErr := s.updateCredentialLastUsed(ctx, cred); txErr != nil {
		s.logger.Warn("Failed to update credential last_used_at", zap.Error(txErr))
	}

	s.logger.Info("Login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID.String()))

	// Clear login failures count
	_ = s.redis.Del(ctx, attemptsKey)

	// 10. Audit log
	accountUUID := uuid.MustParse(account.ID)
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionLoginSuccess,
		req.Username,
		&accountUUID,
		utility.MustMarshalJSON(map[string]any{"account_id": account.ID, "session_id": session.ID.String()}),
		utility.MustMarshalJSON(map[string]any{"ip": req.IP, "user_agent": req.UserAgent}),
	))

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
			s.auditLog(ctx, auditDomain.NewRecord(
				auditDomain.ActionMFALoginFailure,
				"",
				nil,
				utility.MustMarshalJSON(map[string]any{"reason": err.Error()}),
				utility.MustMarshalJSON(map[string]any{"ip": ip, "user_agent": userAgent}),
			))
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
	switch mfaType {
	case "passkey":
		if s.passkeySvc == nil {
			return nil, ErrPasskeyNotAvailable
		}
		// passkey verification is done via HTTP request, here mfaCode is sessionData JSON
		// but the actual validation of Passkey MFA is completed in the controller layer via CompleteMFALogin
		// here we only do token validation, passkey validation result is passed through Redis marker
		passkeyKey := fmt.Sprintf("webauthn:mfa_verified:%s", accountID)
		verified, verr := s.redis.Get(ctx, passkeyKey)
		if verr != nil || verified != "1" {
			return nil, ErrPasskeyNotVerified
		}
		_ = s.redis.Del(ctx, passkeyKey)
	default:
		// TOTP / backup code
		valid, verr := s.mfaSvc.VerifyTOTP(ctx, accountID, mfaCode)
		if verr != nil || !valid {
			valid, verr = s.mfaSvc.VerifyBackupCode(ctx, accountID, mfaCode)
			if verr != nil || !valid {
				return nil, ErrInvalidMFACode
			}
		}
	}

	// 3. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAccountNotFound, err)
	}

	// 4. Create session
	now := time.Now()
	session := &sessionDomain.Session{
		ID:           uuid.New(),
		AccountID:    uuid.MustParse(account.ID),
		IP:           ip,
		UserAgent:    userAgent,
		CreatedAt:    now,
		LastActiveAt: now,
	}
	if account.Username != nil {
		session.Username = *account.Username
	}
	if err := s.sessionSvc.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// 4.5 Enforce concurrent session limit
	s.sessionSvc.EnforceSessionLimit(ctx, account.ID)

	// 5. Get roles
	roles, err := s.roleRepo.FindRolesByAccountID(ctx, account.ID)
	if err != nil {
		s.logger.Warn("Failed to fetch roles for MFA login", zap.Error(err))
		roles = nil
	}
	var roleNames []string
	var allPermissions []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		allPermissions = append(allPermissions, role.Permissions...)
	}

	// 6. Generate tokens
	accessToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID:   account.ID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   session.ID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err := s.tokenSvc.GenerateRefreshToken(ctx, account.ID, "", session.ID.String(), "")
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	s.logger.Info("MFA login successful", zap.String("account_id", account.ID))

	// Audit log
	accountUUID := uuid.MustParse(account.ID)
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionMFALoginSuccess,
		"",
		&accountUUID,
		utility.MustMarshalJSON(map[string]any{"account_id": account.ID, "session_id": session.ID.String()}),
		utility.MustMarshalJSON(map[string]any{"ip": ip, "user_agent": userAgent}),
	))

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
			s.auditLog(ctx, auditDomain.NewRecord(
				auditDomain.ActionLoginFailure,
				accountID,
				nil,
				utility.MustMarshalJSON(map[string]any{"method": "passkey", "account_id": accountID}),
				utility.MustMarshalJSON(map[string]any{"ip": ip, "user_agent": userAgent, "reason": err.Error()}),
			))
		}
	}()

	// 1. Find account
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrAccountNotFound
	}

	// 2. Check account status
	if account.Status != accountDomain.AccountStatusActive {
		return nil, ErrAccountNotActive
	}

	// 3. Check if MFA is required
	mfaEnabled, _ := s.mfaSvc.IsMFAEnabled(ctx, account.ID)
	if mfaEnabled {
		mfaToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
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

	// 4. Create session
	now := time.Now()
	session := &sessionDomain.Session{
		ID:           uuid.New(),
		AccountID:    uuid.MustParse(account.ID),
		IP:           ip,
		UserAgent:    userAgent,
		CreatedAt:    now,
		LastActiveAt: now,
	}
	if account.Username != nil {
		session.Username = *account.Username
	}

	if err := s.sessionSvc.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	s.sessionSvc.EnforceSessionLimit(ctx, account.ID)

	// 5. Get roles and permissions
	roles, err := s.roleRepo.FindRolesByAccountID(ctx, account.ID)
	if err != nil {
		s.logger.Warn("Failed to fetch roles for token", zap.Error(err), zap.String("account_id", account.ID))
		roles = nil
	}

	var roleNames []string
	var allPermissions []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		allPermissions = append(allPermissions, role.Permissions...)
	}

	// 6. Generate Access Token
	accessToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID:   account.ID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   session.ID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 7. Generate Refresh Token
	refreshToken, err := s.tokenSvc.GenerateRefreshToken(ctx, account.ID, "", session.ID.String(), "")
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	s.logger.Info("Passkey login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID.String()))

	// 8. Audit log
	accountUUID := uuid.MustParse(account.ID)
	s.auditLog(ctx, auditDomain.NewRecord(
		auditDomain.ActionLoginSuccess,
		accountID,
		&accountUUID,
		utility.MustMarshalJSON(map[string]any{"method": "passkey", "account_id": account.ID, "session_id": session.ID.String()}),
		utility.MustMarshalJSON(map[string]any{"ip": ip, "user_agent": userAgent}),
	))

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
	// 1. Delete session
	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}

	if err := s.sessionSvc.DeleteSession(ctx, parsedSessionID); err != nil {
		s.logger.Warn("Failed to delete session during logout", zap.Error(err))
	}

	// 2. Revoke Access Token (add to blacklist)
	if accessTokenJTI != "" {
		if err := s.tokenSvc.RevokeAllForSession(ctx, sessionID); err != nil {
			s.logger.Warn("Failed to revoke refresh tokens", zap.Error(err))
		}
	}

	// 3. Audit log
	var acctID *uuid.UUID
	if accountID != "" {
		id := uuid.MustParse(accountID)
		acctID = &id
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

// RefreshTokens refreshes access and refresh tokens
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// 1. Verify and rotate Refresh Token
	newRefreshToken, err := s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	}

	// 2. Verify if the session is still active
	sessionID, err := uuid.Parse(newRefreshToken.SessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSessionID, err)
	}
	session, err := s.sessionSvc.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSessionInvalid, err)
	}

	// 3. Fetch roles and permissions again
	roles, err := s.roleRepo.FindRolesByAccountID(ctx, newRefreshToken.AccountID)
	if err != nil {
		s.logger.Warn("Failed to fetch roles during refresh", zap.Error(err))
		roles = nil
	}

	var roleNames []string
	var allPermissions []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		allPermissions = append(allPermissions, role.Permissions...)
	}

	// 4. Generate new Access Token
	accessToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID:   newRefreshToken.AccountID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   session.ID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 5. Refresh session
	_ = s.sessionSvc.RefreshSession(ctx, sessionID)

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
	}, nil
}

// ValidateSession validates the session
func (s *AuthService) ValidateSession(ctx context.Context, sessionID string) (*sessionDomain.Session, error) {
	parsedID, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session id: %w", err)
	}
	return s.sessionSvc.ValidateSession(ctx, parsedID)
}

// ListSessions lists all active sessions for the account
func (s *AuthService) ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error) {
	return s.sessionSvc.ListSessionsByAccount(ctx, accountID)
}

// RevokeSession revokes specified session
func (s *AuthService) RevokeSession(ctx context.Context, accountID, sessionID string) error {
	parsedID, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}
	return s.sessionSvc.RevokeSession(ctx, accountID, parsedID)
}

// MFAService returns the MFA service instance
func (s *AuthService) MFAService() *MFAService {
	return s.mfaSvc
}

// PasskeyService returns the Passkey service instance
func (s *AuthService) PasskeyService() *PasskeyService {
	return s.passkeySvc
}

// TokenService returns the Token service instance
func (s *AuthService) TokenService() *tokenService.TokenService {
	return s.tokenSvc
}

// ValidateMFAToken validates MFA token and returns claims
func (s *AuthService) ValidateMFAToken(ctx context.Context, mfaToken string) (*tokenDomain.AccessTokenClaims, error) {
	claims, err := s.tokenSvc.ValidateAccessToken(mfaToken)
	if err != nil {
		return nil, ErrInvalidMFAToken
	}
	if claims.Scope != "mfa" {
		return nil, ErrInvalidMFATokenScope
	}
	return claims, nil
}

// MarkPasskeyMFAVerified marks passkey MFA as verified
func (s *AuthService) MarkPasskeyMFAVerified(ctx context.Context, accountID string) error {
	key := fmt.Sprintf("webauthn:mfa_verified:%s", accountID)
	return s.redis.Set(ctx, key, "1", challengeTTL)
}

func (s *AuthService) auditLog(ctx context.Context, record *auditDomain.AuditRecord) {
	if s.auditor != nil {
		if err := s.auditor.Log(ctx, record); err != nil {
			s.logger.Warn("Failed to submit audit record", zap.Error(err))
		}
	}
}

// updateCredentialLastUsed updates the last used time of a credential
func (s *AuthService) updateCredentialLastUsed(ctx context.Context, cred *accountDomain.Credential) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.credentialRepo.UpdateCredential(ctx, tx, cred); err != nil {
		return fmt.Errorf("update credential: %w", err)
	}

	return tx.Commit()
}
