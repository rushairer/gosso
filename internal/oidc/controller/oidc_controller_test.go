package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	"github.com/rushairer/gosso/internal/testutil"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// ──────────────────────────────────────────────
// Mock AccountService
// ──────────────────────────────────────────────

type mockAccountService struct {
	findByIDFn func() (*accountDomain.Account, error)
}

func (m *mockAccountService) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountService) FindAccountByID(_ context.Context, _ string) (*accountDomain.Account, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn()
	}
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountService) FindAccountByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountService) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	return nil
}
func (m *mockAccountService) SoftDeleteAccount(_ context.Context, _ string) error    { return nil }
func (m *mockAccountService) VerifyCredential(_ context.Context, _ string) error     { return nil }
func (m *mockAccountService) ChangePassword(_ context.Context, _, _, _ string) error { return nil }
func (m *mockAccountService) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockAccountService) UnbindFederatedIdentity(_ context.Context, _, _ string) error { return nil }
func (m *mockAccountService) AssignRole(_ context.Context, _, _ string) error           { return nil }
func (m *mockAccountService) RemoveRole(_ context.Context, _, _ string) error           { return nil }
func (m *mockAccountService) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	return nil, 0, nil
}
func (m *mockAccountService) SuspendAccount(_ context.Context, _ string) error  { return nil }
func (m *mockAccountService) ActivateAccount(_ context.Context, _ string) error { return nil }
func (m *mockAccountService) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	return nil, nil
}

func (m *mockAccountService) SetSessionRevoker(_ accountService.SessionRevoker)            {}
func (m *mockAccountService) SetOAuth2ClientDeleter(_ accountService.OAuth2ClientDeleter)  {}

// ──────────────────────────────────────────────
// Mock CredentialRepository
// ──────────────────────────────────────────────

type mockCredentialRepo struct {
	findByAcctTypeFn func() ([]*accountDomain.Credential, error)
}

func (m *mockCredentialRepo) CreateCredentials(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
	return nil
}
func (m *mockCredentialRepo) FindByAccountAndType(_ context.Context, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAcctTypeFn != nil {
		return m.findByAcctTypeFn()
	}
	return nil, nil
}
func (m *mockCredentialRepo) FindByTypeAndIdentifier(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockCredentialRepo) FindPasswordCredential(_ context.Context, _ string) (*accountDomain.Credential, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockCredentialRepo) UpdateCredential(_ context.Context, _ *sql.Tx, _ *accountDomain.Credential) error {
	return nil
}
func (m *mockCredentialRepo) SoftDeleteCredentialsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockCredentialRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockCredentialRepo) VerifyFirstUnverifiedTOTP(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
	return false, nil
}
func (m *mockCredentialRepo) FindByAccountAndTypeForUpdate(_ context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return nil, nil
}

// ──────────────────────────────────────────────
// Mock OAuth2ClientRepository
// ──────────────────────────────────────────────

type mockClientRepo struct {
	findByClientIDFn func() (*oauth2Domain.OAuth2Client, error)
}

func (m *mockClientRepo) Create(_ context.Context, _ *sql.Tx, _ *oauth2Domain.OAuth2Client) error {
	return nil
}
func (m *mockClientRepo) FindByClientID(_ context.Context, _ string) (*oauth2Domain.OAuth2Client, error) {
	if m.findByClientIDFn != nil {
		return m.findByClientIDFn()
	}
	return nil, oauth2Domain.ErrClientNotFound
}
func (m *mockClientRepo) FindByAccountID(_ context.Context, _ string) ([]*oauth2Domain.OAuth2Client, error) {
	return nil, nil
}
func (m *mockClientRepo) Update(_ context.Context, _ *sql.Tx, _ *oauth2Domain.OAuth2Client) error {
	return nil
}
func (m *mockClientRepo) SoftDelete(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockClientRepo) SoftDeleteByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

var _ oauth2Repo.OAuth2ClientRepository = (*mockClientRepo)(nil)

// ──────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────

func setupUserInfoEngine(accountSvc *mockAccountService, credRepo *mockCredentialRepo, claims *tokenDomain.AccessTokenClaims) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	engine.Use(func(ctx *gin.Context) {
		if claims != nil {
			ctx.Set(middleware.ContextKeyClaims, claims)
		}
		ctx.Next()
	})

	discoverySvc := oidcService.NewDiscoveryService("https://sso.example.com")
	userInfoSvc := oidcService.NewUserInfoService(accountSvc, credRepo, nil)

	ctrl := NewOIDCController(discoverySvc, nil, userInfoSvc, nil, nil, nil, "https://sso.example.com", zap.NewNop())
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	return engine
}

func newTestAccount() *accountDomain.Account {
	username := "testuser"
	avatarURL := "https://example.com/avatar.png"
	return &accountDomain.Account{
		ID:          "account-001",
		Username:    &username,
		DisplayName: "Test User",
		AvatarURL:   &avatarURL,
		Status:      accountDomain.AccountStatusActive,
		Locale:      "en",
	}
}

// ──────────────────────────────────────────────
// Discovery Tests
// ──────────────────────────────────────────────

func TestDiscovery_Success(t *testing.T) {
	engine := setupUserInfoEngine(&mockAccountService{}, &mockCredentialRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "https://sso.example.com", resp["issuer"])
	assert.NotNil(t, resp["authorization_endpoint"])
	assert.NotNil(t, resp["token_endpoint"])
	assert.NotNil(t, resp["jwks_uri"])
	assert.NotNil(t, resp["userinfo_endpoint"])
}

// ──────────────────────────────────────────────
// UserInfo Tests
// ──────────────────────────────────────────────

func TestUserInfo_ProfileScope(t *testing.T) {
	account := newTestAccount()
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return account, nil
		},
	}
	engine := setupUserInfoEngine(accountSvc, &mockCredentialRepo{}, &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		Scope:     "openid profile",
	})

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "account-001", resp["sub"])
	assert.Equal(t, "Test User", resp["name"])
	assert.Equal(t, "testuser", resp["preferred_username"])
	assert.Equal(t, "https://example.com/avatar.png", resp["picture"])
	assert.Equal(t, "en", resp["locale"])
}

func TestUserInfo_EmailScope(t *testing.T) {
	account := newTestAccount()
	email := "test@example.com"
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return account, nil
		},
	}
	credRepo := &mockCredentialRepo{
		findByAcctTypeFn: func() ([]*accountDomain.Credential, error) {
			return []*accountDomain.Credential{
				{Identifier: &email, Verified: true},
			}, nil
		},
	}
	engine := setupUserInfoEngine(accountSvc, credRepo, &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		Scope:     "openid email",
	})

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "test@example.com", resp["email"])
	assert.Equal(t, true, resp["email_verified"])
}

func TestUserInfo_NoClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	discoverySvc := oidcService.NewDiscoveryService("https://sso.example.com")
	userInfoSvc := oidcService.NewUserInfoService(&mockAccountService{}, &mockCredentialRepo{}, nil)
	ctrl := NewOIDCController(discoverySvc, nil, userInfoSvc, nil, nil, nil, "https://sso.example.com", zap.NewNop())
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserInfo_AccountNotActive(t *testing.T) {
	account := newTestAccount()
	account.Status = accountDomain.AccountStatusSuspended
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return account, nil
		},
	}
	engine := setupUserInfoEngine(accountSvc, &mockCredentialRepo{}, &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		Scope:     "openid profile",
	})

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUserInfo_AccountNotFound(t *testing.T) {
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	engine := setupUserInfoEngine(accountSvc, &mockCredentialRepo{}, &tokenDomain.AccessTokenClaims{
		AccountID: "nonexistent",
		Scope:     "openid profile",
	})

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUserInfo_PhoneScope(t *testing.T) {
	account := newTestAccount()
	phone := "+8613800138000"
	accountSvc := &mockAccountService{
		findByIDFn: func() (*accountDomain.Account, error) {
			return account, nil
		},
	}
	credRepo := &mockCredentialRepo{
		findByAcctTypeFn: func() ([]*accountDomain.Credential, error) {
			return []*accountDomain.Credential{
				{Identifier: &phone, Verified: false},
			}, nil
		},
	}
	engine := setupUserInfoEngine(accountSvc, credRepo, &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		Scope:     "openid phone",
	})

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "+8613800138000", resp["phone_number"])
	assert.Equal(t, false, resp["phone_number_verified"])
}

// ──────────────────────────────────────────────
// Logout Test Helpers
// ──────────────────────────────────────────────

func setupTestKeyService(t *testing.T) *tokenService.KeyService {
	t.Helper()
	keySvc, err := tokenService.NewKeyService("", "", zap.NewNop())
	require.NoError(t, err)
	return keySvc
}

func signIDToken(t *testing.T, keySvc *tokenService.KeyService, issuer string, accountID string, audience []string, expired bool) string {
	t.Helper()
	claims := &oidcService.IDTokenClaims{}
	claims.Subject = accountID
	claims.Issuer = issuer
	claims.Audience = audience
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	if expired {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(-1 * time.Hour))
	} else {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(1 * time.Hour))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keySvc.KeyID()
	tokenString, err := token.SignedString(keySvc.PrivateKey())
	require.NoError(t, err)
	return tokenString
}

func signAccessToken(t *testing.T, keySvc *tokenService.KeyService, issuer, accountID, sessionID string) string {
	t.Helper()
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: accountID,
		SessionID: sessionID,
	}
	claims.Issuer = issuer
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(15 * time.Minute))

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keySvc.KeyID()
	tokenString, err := token.SignedString(keySvc.PrivateKey())
	require.NoError(t, err)
	return tokenString
}

func setupLogoutEngine(t *testing.T, clientRepo *mockClientRepo) (*gin.Engine, *tokenService.KeyService) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())
	discoverySvc := oidcService.NewDiscoveryService("https://sso.example.com")

	ctrl := NewOIDCController(discoverySvc, nil, nil, logoutSvc, clientRepo, tokenSvc, "https://sso.example.com", zap.NewNop())

	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	return engine, keySvc
}

// ──────────────────────────────────────────────
// Logout Tests — id_token_hint path
// ──────────────────────────────────────────────

func TestLogout_InvalidIDTokenHint(t *testing.T) {
	engine, _ := setupLogoutEngine(t, &mockClientRepo{})

	form := url.Values{"id_token_hint": {"not-a-jwt"}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// Invalid id_token_hint is silently skipped per OIDC RP-Initiated Logout spec
	// (id_token_hint is optional). Without a Bearer token, this falls through
	// to the anonymous success path.
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogout_ExpiredIDTokenHint(t *testing.T) {
	// Expired tokens SHOULD be accepted per OIDC RP-Initiated Logout spec.
	// This is validated at the service layer (TestValidateIDTokenHint_ExpiredTokenAccepted).
	// At the controller layer, the accepted token triggers LogoutByAccountID which
	// gracefully handles missing session service (warns and continues).
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())

	ctrl := NewOIDCController(nil, nil, nil, logoutSvc, nil, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	expiredToken := signIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, true)

	form := url.Values{"id_token_hint": {expiredToken}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// Token is accepted by ValidateIDTokenHint (expired OK per spec).
	// LogoutByAccountID succeeds (session service gracefully skipped).
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "logged_out", data["status"])
}

func TestLogout_IDTokenHint_WrongIssuer(t *testing.T) {
	// Sign with a different issuer
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://other-issuer.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())
	discoverySvc := oidcService.NewDiscoveryService("https://sso.example.com")

	ctrl := NewOIDCController(discoverySvc, nil, nil, logoutSvc, nil, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	// Token signed by same key but issuer in claims differs from server's issuer
	token := signIDToken(t, keySvc, "https://other-issuer.com", "account-001", []string{"client-001"}, false)

	form := url.Values{"id_token_hint": {token}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// Wrong issuer → validation fails → falls through to anonymous success
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogout_IDTokenHint_NoAudience(t *testing.T) {
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())
	discoverySvc := oidcService.NewDiscoveryService("https://sso.example.com")

	ctrl := NewOIDCController(discoverySvc, nil, nil, logoutSvc, nil, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	token := signIDToken(t, keySvc, "https://sso.example.com", "account-001", nil, false)

	form := url.Values{"id_token_hint": {token}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// No audience → validation fails → falls through to anonymous success
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogout_IDTokenHint_WrongSignature(t *testing.T) {
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())

	// Sign with a DIFFERENT key service
	otherKeySvc, err := tokenService.NewKeyService("", "", zap.NewNop())
	require.NoError(t, err)

	ctrl := NewOIDCController(nil, nil, nil, logoutSvc, nil, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	token := signIDToken(t, otherKeySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	form := url.Values{"id_token_hint": {token}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// Wrong signature → validation fails → falls through to anonymous success
	assert.Equal(t, http.StatusOK, w.Code)
}

// ──────────────────────────────────────────────
// Logout Tests — Bearer token fallback
// ──────────────────────────────────────────────

func TestLogout_BearerToken_InvalidSignature(t *testing.T) {
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())

	otherKeySvc, err := tokenService.NewKeyService("", "", zap.NewNop())
	require.NoError(t, err)

	ctrl := NewOIDCController(nil, nil, nil, logoutSvc, nil, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	// Access token signed with a different key
	token := signAccessToken(t, otherKeySvc, "https://sso.example.com", "account-001", "session-001")

	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// Invalid Bearer token → 401 Unauthorized
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(http.StatusUnauthorized), resp["code"])
}

// ──────────────────────────────────────────────
// Logout Tests — post_logout_redirect_uri
// ──────────────────────────────────────────────

func TestLogout_PostLogoutRedirect_InvalidURI(t *testing.T) {
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())
	discoverySvc := oidcService.NewDiscoveryService("https://sso.example.com")

	clientRepo := &mockClientRepo{
		findByClientIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return &oauth2Domain.OAuth2Client{
				ClientID:               "client-001",
				PostLogoutRedirectURIs: []string{"https://app.example.com/logout"},
			}, nil
		},
	}

	ctrl := NewOIDCController(discoverySvc, nil, nil, logoutSvc, clientRepo, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	token := signIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	// Request with a redirect URI NOT in the client's registered list
	form := url.Values{
		"id_token_hint":           {token},
		"client_id":               {"client-001"},
		"post_logout_redirect_uri": {"https://evil.com/redirect"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogout_PostLogoutRedirect_ValidURI(t *testing.T) {
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())
	discoverySvc := oidcService.NewDiscoveryService("https://sso.example.com")

	clientRepo := &mockClientRepo{
		findByClientIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return &oauth2Domain.OAuth2Client{
				ClientID:               "client-001",
				PostLogoutRedirectURIs: []string{"https://app.example.com/logout"},
			}, nil
		},
	}

	ctrl := NewOIDCController(discoverySvc, nil, nil, logoutSvc, clientRepo, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	token := signIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	form := url.Values{
		"id_token_hint":           {token},
		"client_id":               {"client-001"},
		"post_logout_redirect_uri": {"https://app.example.com/logout"},
		"state":                   {"test-state"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://app.example.com/logout")
	assert.Contains(t, location, "state=test-state")
}

func TestLogout_PostLogoutRedirect_ClientNotFound(t *testing.T) {
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())

	clientRepo := &mockClientRepo{
		findByClientIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return nil, oauth2Domain.ErrClientNotFound
		},
	}

	ctrl := NewOIDCController(nil, nil, nil, logoutSvc, clientRepo, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	token := signIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	form := url.Values{
		"id_token_hint":           {token},
		"client_id":               {"client-001"},
		"post_logout_redirect_uri": {"https://app.example.com/logout"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// Client lookup fails → falls through to default response
	assert.Equal(t, http.StatusOK, w.Code)
}

// ──────────────────────────────────────────────
// Logout Tests — client_id mismatch with id_token_hint
// ──────────────────────────────────────────────

func TestLogout_ClientIDMismatch(t *testing.T) {
	keySvc := setupTestKeyService(t)
	redisClient, _ := testutil.SetupTestRedis(t)
	tokenSvc := tokenService.NewTokenService(keySvc, "https://sso.example.com", 15*time.Minute, 720*time.Hour, redisClient, nil, zap.NewNop())
	logoutSvc := oidcService.NewLogoutService(tokenSvc, nil, "https://sso.example.com", zap.NewNop())

	ctrl := NewOIDCController(nil, nil, nil, logoutSvc, nil, tokenSvc, "https://sso.example.com", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/.well-known/openid-configuration", ctrl.Discovery)
	oidcGroup := engine.Group("/oidc")
	ctrl.RegisterRoutes(oidcGroup, func(ctx *gin.Context) { ctx.Next() })

	// Token has audience ["client-001"], but request claims client_id=client-999
	token := signIDToken(t, keySvc, "https://sso.example.com", "account-001", []string{"client-001"}, false)

	form := url.Values{
		"id_token_hint": {token},
		"client_id":     {"client-999"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// Logout Tests — no session
// ──────────────────────────────────────────────

func TestLogout_NoSession(t *testing.T) {
	engine, _ := setupLogoutEngine(t, &mockClientRepo{})

	req := httptest.NewRequest(http.MethodPost, "/oidc/logout", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// No id_token_hint, no Bearer → anonymous logout succeeds
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(http.StatusOK), resp["code"])
}

// ──────────────────────────────────────────────
// Logout Tests — Discovery includes end_session_endpoint
// ──────────────────────────────────────────────

func TestDiscovery_EndSessionEndpoint(t *testing.T) {
	engine, _ := setupLogoutEngine(t, &mockClientRepo{})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "https://sso.example.com/oidc/logout", resp["end_session_endpoint"])
}
