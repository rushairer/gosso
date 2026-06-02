package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/auth/middleware"
	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	oidcService "github.com/rushairer/gosso/internal/oidc/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
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
func (m *mockAccountService) SoftDeleteAccount(_ context.Context, _ string) error     { return nil }
func (m *mockAccountService) VerifyCredential(_ context.Context, _ string) error       { return nil }
func (m *mockAccountService) ChangePassword(_ context.Context, _, _, _ string) error    { return nil }
func (m *mockAccountService) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return nil
}
func (m *mockAccountService) UnbindFederatedIdentity(_ context.Context, _ string) error  { return nil }
func (m *mockAccountService) AssignRole(_ context.Context, _, _ string) error            { return nil }
func (m *mockAccountService) RemoveRole(_ context.Context, _, _ string) error            { return nil }
func (m *mockAccountService) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	return nil, 0, nil
}
func (m *mockAccountService) SuspendAccount(_ context.Context, _ string) error   { return nil }
func (m *mockAccountService) ActivateAccount(_ context.Context, _ string) error  { return nil }
func (m *mockAccountService) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	return nil, nil
}

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

	ctrl := NewOIDCController(discoverySvc, nil, userInfoSvc, zap.NewNop())
	ctrl.RegisterRoutes(engine, func(ctx *gin.Context) { ctx.Next() })

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
	ctrl := NewOIDCController(discoverySvc, nil, userInfoSvc, zap.NewNop())
	ctrl.RegisterRoutes(engine, func(ctx *gin.Context) { ctx.Next() })

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
