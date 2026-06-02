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

// buildTokenClaims fetches roles and permissions for an account and builds token claims.
func (s *AuthService) buildTokenClaims(ctx context.Context, accountID, sessionID string) *tokenDomain.AccessTokenClaims {
	roles, err := s.roleRepo.FindRolesByAccountID(ctx, accountID)
	if err != nil {
		s.logger.Warn("Failed to fetch roles for token", zap.Error(err), zap.String("account_id", accountID))
		roles = nil
	}

	var roleNames []string
	var allPermissions []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		allPermissions = append(allPermissions, role.Permissions...)
	}

	return &tokenDomain.AccessTokenClaims{
		AccountID:   accountID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   sessionID,
	}
}

// createSessionAndTokens creates a session, generates access and refresh tokens.
func (s *AuthService) createSessionAndTokens(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
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
		return nil, "", nil, fmt.Errorf("create session: %w", err)
	}

	s.sessionSvc.EnforceSessionLimit(ctx, account.ID)

	claims := s.buildTokenClaims(ctx, account.ID, session.ID.String())

	accessToken, err := s.tokenSvc.GenerateAccessToken(claims)
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err := s.tokenSvc.GenerateRefreshToken(ctx, account.ID, "", session.ID.String(), "")
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate refresh token: %w", err)
	}

	return session, accessToken, refreshToken, nil
}

// loginAuditLogs logs a login success or failure audit record.
func (s *AuthService) loginAuditLogs(ctx context.Context, action string, username string, accountID *uuid.UUID, detail map[string]any, meta map[string]any) {
	s.auditLog(ctx, auditDomain.NewRecord(
		action,
		username,
		accountID,
		utility.MustMarshalJSON(detail),
		utility.MustMarshalJSON(meta),
	))
}
