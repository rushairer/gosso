package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"go.uber.org/zap"
)

// OAuthProviderConfig 单个 OAuth 提供商配置
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	TokenURL     string
	UserInfoURL  string
}

// SocialLoginService 社交登录服务
type SocialLoginService struct {
	db                *sql.DB
	accountSvc        accountService.AccountService
	sessionSvc        *sessionService.SessionService
	tokenSvc          *tokenService.TokenService
	credentialRepo    accountRepo.CredentialRepository
	roleRepo          accountRepo.RoleRepository
	federatedIdentityRepo accountRepo.FederatedIdentityRepository
	providers         map[string]*OAuthProviderConfig
	logger            *zap.Logger
}

// NewSocialLoginService 创建社交登录服务
func NewSocialLoginService(
	db *sql.DB,
	accountSvc accountService.AccountService,
	sessionSvc *sessionService.SessionService,
	tokenSvc *tokenService.TokenService,
	credentialRepo accountRepo.CredentialRepository,
	roleRepo accountRepo.RoleRepository,
	federatedIdentityRepo accountRepo.FederatedIdentityRepository,
	providers map[string]*OAuthProviderConfig,
	logger *zap.Logger,
) *SocialLoginService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SocialLoginService{
		db:                    db,
		accountSvc:            accountSvc,
		sessionSvc:            sessionSvc,
		tokenSvc:              tokenSvc,
		credentialRepo:        credentialRepo,
		roleRepo:              roleRepo,
		federatedIdentityRepo: federatedIdentityRepo,
		providers:             providers,
		logger:                logger,
	}
}

// GetAuthURL 获取第三方授权 URL
func (s *SocialLoginService) GetAuthURL(ctx context.Context, provider, state string) (string, error) {
	p, ok := s.providers[provider]
	if !ok {
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}

	var authURL string
	switch provider {
	case "google":
		authURL = "https://accounts.google.com/o/oauth2/v2/auth"
	case "github":
		authURL = "https://github.com/login/oauth/authorize"
	case "wechat":
		authURL = "https://open.weixin.qq.com/connect/qrconnect"
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}

	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("redirect_uri", p.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(p.Scopes, " "))
	params.Set("state", state)

	return authURL + "?" + params.Encode(), nil
}

// HandleCallback 处理第三方回调
func (s *SocialLoginService) HandleCallback(ctx context.Context, provider, code, ip, userAgent string) (*LoginResult, error) {
	p, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	// 1. 用 code 换取 access_token
	accessToken, err := s.exchangeCode(ctx, p, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	// 2. 获取用户信息
	providerUserID, email, name, err := s.fetchUserInfo(ctx, provider, p, accessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch user info: %w", err)
	}

	// 3. 查找已有联邦身份
	identity, err := s.federatedIdentityRepo.FindByProvider(ctx, accountDomain.Provider(provider), providerUserID)
	if err == nil && identity != nil {
		// 已有身份 → 直接登录
		return s.loginExistingUser(ctx, identity.AccountID, ip, userAgent)
	}

	// 4. 新用户 → 创建账号 + 绑定身份
	return s.createNewUser(ctx, provider, providerUserID, email, name, ip, userAgent)
}

func (s *SocialLoginService) exchangeCode(ctx context.Context, p *OAuthProviderConfig, code string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("redirect_uri", p.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %d %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}

	return tokenResp.AccessToken, nil
}

func (s *SocialLoginService) fetchUserInfo(ctx context.Context, provider string, p *OAuthProviderConfig, accessToken string) (providerUserID, email, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.UserInfoURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("read userinfo: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("userinfo request failed: %d", resp.StatusCode)
	}

	var userInfo map[string]any
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return "", "", "", fmt.Errorf("parse userinfo: %w", err)
	}

	switch provider {
	case "google":
		providerUserID = fmt.Sprintf("%v", userInfo["id"])
		email, _ = userInfo["email"].(string)
		name, _ = userInfo["name"].(string)
	case "github":
		providerUserID = fmt.Sprintf("%.0f", userInfo["id"])
		email, _ = userInfo["email"].(string)
		name, _ = userInfo["name"].(string)
	case "wechat":
		providerUserID, _ = userInfo["openid"].(string)
		nickname, _ := userInfo["nickname"].(string)
		name = nickname
	}

	return providerUserID, email, name, nil
}

func (s *SocialLoginService) loginExistingUser(ctx context.Context, accountID, ip, userAgent string) (*LoginResult, error) {
	account, err := s.accountSvc.FindAccountByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find account: %w", err)
	}

	return s.createSessionAndTokens(ctx, account, ip, userAgent)
}

func (s *SocialLoginService) createNewUser(ctx context.Context, provider, providerUserID, email, name, ip, userAgent string) (*LoginResult, error) {
	if name == "" {
		name = "User"
	}

	now := time.Now()
	accountID := uuid.New().String()

	// 创建账号
	account := &accountDomain.Account{
		ID:          accountID,
		DisplayName: name,
		Status:      accountDomain.AccountStatusActive,
		Locale:      "en",
		Timezone:    "UTC",
		Metadata:    make(map[string]any),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 插入账号
	_, err = tx.ExecContext(ctx,
		`INSERT INTO accounts (id, display_name, status, locale, timezone, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		account.ID, account.DisplayName, account.Status, account.Locale, account.Timezone,
		`{}`, account.CreatedAt, account.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert account: %w", err)
	}

	// 创建邮箱凭证
	if email != "" {
		emailCred := accountDomain.NewEmailCredential(accountID, email)
		emailCred.Verify()
		_, err = tx.ExecContext(ctx,
			`INSERT INTO account_credentials (id, account_id, credential_type, identifier, credential_value, verified, primary_credential, metadata, created_at, verified_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			emailCred.ID, emailCred.AccountID, emailCred.Type, emailCred.Identifier, "",
			emailCred.Verified, true, `{}`, emailCred.CreatedAt, emailCred.VerifiedAt,
		)
		if err != nil {
			s.logger.Warn("Failed to create email credential for social login", zap.Error(err))
		}
	}

	// 创建联邦身份
	identity := accountDomain.NewFederatedIdentity(accountID, accountDomain.Provider(provider), providerUserID, nil)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO federated_identities (id, account_id, provider, provider_user_id, profile, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		identity.ID, identity.AccountID, identity.Provider, identity.ProviderUserID,
		`{}`, identity.CreatedAt, identity.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert federated identity: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return s.createSessionAndTokens(ctx, account, ip, userAgent)
}

func (s *SocialLoginService) createSessionAndTokens(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*LoginResult, error) {
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

	roles, _ := s.roleRepo.FindRolesByAccountID(ctx, account.ID)
	var roleNames []string
	var allPermissions []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
		allPermissions = append(allPermissions, role.Permissions...)
	}

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

	return &LoginResult{
		Account:      account,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}
