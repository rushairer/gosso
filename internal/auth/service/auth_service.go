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

// LoginRequest 登录请求
type LoginRequest struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}

// LoginResult 登录结果
type LoginResult struct {
	Account      *accountDomain.Account
	Session      *sessionDomain.Session
	AccessToken  string
	RefreshToken string
	RequiresMFA  bool
	MFATypes     []string `json:"mfa_types,omitempty"`
}

// RefreshResult 刷新令牌结果
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
}

// AuthService 认证编排服务
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

// NewAuthService 创建认证服务实例
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

// LoginByUsernamePassword 用户名/密码登录
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

	// 0. 检查登录失败限速
	attemptsKey := fmt.Sprintf("login_attempts:%s", req.Username)
	count, err := s.redis.IncrWithExpiry(ctx, attemptsKey, 15*time.Minute)
	if err == nil && count > 5 {
		return nil, ErrAccountLocked
	}

	// 1. 查找账号
	account, err := s.accountSvc.FindAccountByUsername(ctx, req.Username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 2. 检查账号状态
	if account.Status != accountDomain.AccountStatusActive {
		return nil, ErrAccountNotActive
	}

	// 3. 查找密码凭证
	cred, err := s.credentialRepo.FindPasswordCredential(ctx, account.ID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 4. 验证密码
	if !cred.VerifyPassword(req.Password) {
		return nil, ErrInvalidCredentials
	}

	// 4.5 检查是否需要 MFA
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
			AccessToken: mfaToken, // 短期 MFA session token
			MFATypes:    s.mfaSvc.GetMFATypes(ctx, account.ID),
		}, nil
	}

	// 5. 创建会话
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

	// 5.5 强制执行并发会话限制
	s.sessionSvc.EnforceSessionLimit(ctx, account.ID)

	// 6. 获取角色和权限
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

	// 7. 生成 Access Token
	accessToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID:   account.ID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   session.ID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 8. 生成 Refresh Token
	refreshToken, err := s.tokenSvc.GenerateRefreshToken(ctx, account.ID, "", session.ID.String(), "")
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// 9. 更新凭证最后使用时间
	cred.MarkUsed()
	if txErr := s.updateCredentialLastUsed(ctx, cred); txErr != nil {
		s.logger.Warn("Failed to update credential last_used_at", zap.Error(txErr))
	}

	s.logger.Info("Login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID.String()))

	// 清除登录失败计数
	_ = s.redis.Del(ctx, attemptsKey)

	// 10. 审计日志
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

// VerifyMFALogin MFA 验证后完成登录
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

	// 1. 验证 MFA token
	claims, err := s.tokenSvc.ValidateAccessToken(mfaToken)
	if err != nil {
		return nil, ErrInvalidMFAToken
	}
	if claims.Scope != "mfa" {
		return nil, ErrInvalidMFATokenScope
	}
	accountID := claims.AccountID

	// 2. 根据 MFA 类型验证
	switch mfaType {
	case "passkey":
		if s.passkeySvc == nil {
			return nil, ErrPasskeyNotAvailable
		}
		// passkey 验证通过 HTTP request 完成，此处 mfaCode 是 sessionData JSON
		// 但 Passkey MFA 的实际验证在 controller 层通过 CompleteMFALogin 完成
		// 这里仅做 token 验证，passkey 验证结果通过 Redis 标记传递
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

	// 3. 查找账号
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAccountNotFound, err)
	}

	// 4. 创建会话
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

	// 4.5 强制执行并发会话限制
	s.sessionSvc.EnforceSessionLimit(ctx, account.ID)

	// 5. 获取角色
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

	// 6. 生成 tokens
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

	// 审计日志
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

// LoginByPasskey 通过 Passkey 验证后直接登录（跳过密码验证）
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

	// 1. 查找账号
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, ErrAccountNotFound
	}

	// 2. 检查账号状态
	if account.Status != accountDomain.AccountStatusActive {
		return nil, ErrAccountNotActive
	}

	// 3. 检查是否需要 MFA
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

	// 4. 创建会话
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

	// 5. 获取角色和权限
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

	// 6. 生成 Access Token
	accessToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID:   account.ID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   session.ID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 7. 生成 Refresh Token
	refreshToken, err := s.tokenSvc.GenerateRefreshToken(ctx, account.ID, "", session.ID.String(), "")
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	s.logger.Info("Passkey login successful",
		zap.String("account_id", account.ID),
		zap.String("session_id", session.ID.String()))

	// 8. 审计日志
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

// Logout 注销：删除会话 + 撤销令牌
func (s *AuthService) Logout(ctx context.Context, accountID, sessionID string, accessTokenJTI string, tokenExpiresAt time.Time) error {
	// 1. 删除会话
	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}

	if err := s.sessionSvc.DeleteSession(ctx, parsedSessionID); err != nil {
		s.logger.Warn("Failed to delete session during logout", zap.Error(err))
	}

	// 2. 撤销 Access Token（加入黑名单）
	if accessTokenJTI != "" {
		if err := s.tokenSvc.RevokeAllForSession(ctx, sessionID); err != nil {
			s.logger.Warn("Failed to revoke refresh tokens", zap.Error(err))
		}
	}

	// 3. 审计日志
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

// RefreshTokens 刷新令牌
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// 1. 验证并轮转 Refresh Token
	newRefreshToken, err := s.tokenSvc.RotateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefreshToken, err)
	}

	// 2. 验证会话是否仍然有效
	sessionID, err := uuid.Parse(newRefreshToken.SessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSessionID, err)
	}
	session, err := s.sessionSvc.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSessionInvalid, err)
	}

	// 3. 重新获取角色和权限
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

	// 4. 生成新 Access Token
	accessToken, err := s.tokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID:   newRefreshToken.AccountID,
		Roles:       roleNames,
		Permissions: allPermissions,
		SessionID:   session.ID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 5. 刷新会话
	_ = s.sessionSvc.RefreshSession(ctx, sessionID)

	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
	}, nil
}

// ValidateSession 验证会话
func (s *AuthService) ValidateSession(ctx context.Context, sessionID string) (*sessionDomain.Session, error) {
	parsedID, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session id: %w", err)
	}
	return s.sessionSvc.ValidateSession(ctx, parsedID)
}

// ListSessions 列出账号的所有活跃会话
func (s *AuthService) ListSessions(ctx context.Context, accountID string) ([]*sessionDomain.Session, error) {
	return s.sessionSvc.ListSessionsByAccount(ctx, accountID)
}

// RevokeSession 撤销指定会话
func (s *AuthService) RevokeSession(ctx context.Context, accountID, sessionID string) error {
	parsedID, err := uuid.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}
	return s.sessionSvc.RevokeSession(ctx, accountID, parsedID)
}

// MFAService 返回 MFA 服务实例
func (s *AuthService) MFAService() *MFAService {
	return s.mfaSvc
}

// PasskeyService 返回 Passkey 服务实例
func (s *AuthService) PasskeyService() *PasskeyService {
	return s.passkeySvc
}

// TokenService 返回 Token 服务实例
func (s *AuthService) TokenService() *tokenService.TokenService {
	return s.tokenSvc
}

// ValidateMFAToken 验证 MFA token 并返回 claims
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

// MarkPasskeyMFAVerified 标记 passkey MFA 已通过验证
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

// updateCredentialLastUsed 更新凭证最后使用时间
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
