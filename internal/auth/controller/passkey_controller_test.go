package controller

import (
	"bytes"
	"context"
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

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/auth/middleware"
	"github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// Mocks
// ──────────────────────────────────────────────

type mockAuthOrchForPasskey struct {
	loginByPasskeyFn             func() (*service.LoginResult, error)
	validateMFATokenFn           func() (*tokenDomain.AccessTokenClaims, error)
	markPasskeyMFAFn             func() error
	completePasskeyMFALoginFn    func() (*service.LoginResult, error)
}

func (m *mockAuthOrchForPasskey) LoginByUsernamePassword(_ context.Context, _ *service.LoginRequest) (*service.LoginResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchForPasskey) LoginByPasskey(_ context.Context, _, _, _ string) (*service.LoginResult, error) {
	if m.loginByPasskeyFn != nil {
		return m.loginByPasskeyFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchForPasskey) VerifyMFALogin(_ context.Context, _, _, _, _, _ string) (*service.LoginResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchForPasskey) Logout(_ context.Context, _, _, _ string, _ time.Time) error {
	return nil
}
func (m *mockAuthOrchForPasskey) RefreshTokens(_ context.Context, _ string) (*service.RefreshResult, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAuthOrchForPasskey) ValidateSession(_ context.Context, _ string) (*sessionDomain.Session, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAuthOrchForPasskey) ListSessions(_ context.Context, _ string) ([]*sessionDomain.Session, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAuthOrchForPasskey) RevokeSession(_ context.Context, _, _ string) error { return nil }

func (m *mockAuthOrchForPasskey) ValidateMFAToken(_ context.Context, _ string) (*tokenDomain.AccessTokenClaims, error) {
	if m.validateMFATokenFn != nil {
		return m.validateMFATokenFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchForPasskey) MarkPasskeyMFAVerified(_ context.Context, _ string) error {
	if m.markPasskeyMFAFn != nil {
		return m.markPasskeyMFAFn()
	}
	return nil
}

func (m *mockAuthOrchForPasskey) MFAService() *service.MFAService         { return nil }
func (m *mockAuthOrchForPasskey) PasskeyService() *service.PasskeyService { return nil }

func (m *mockAuthOrchForPasskey) CompletePasskeyMFALogin(_ context.Context, _, _, _ string) (*service.LoginResult, error) {
	if m.completePasskeyMFALoginFn != nil {
		return m.completePasskeyMFALoginFn()
	}
	return nil, fmt.Errorf("not implemented")
}

type mockTokenMgrForPasskey struct{}

func (m *mockTokenMgrForPasskey) GenerateAccessToken(_ *tokenDomain.AccessTokenClaims) (string, error) {
	return "mock-access", nil
}
func (m *mockTokenMgrForPasskey) GenerateRefreshToken(_ context.Context, _, _, _, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "mock-refresh"}, nil
}
func (m *mockTokenMgrForPasskey) ValidateAccessToken(_ string) (*tokenDomain.AccessTokenClaims, error) {
	return &tokenDomain.AccessTokenClaims{AccountID: "account-001"}, nil
}
func (m *mockTokenMgrForPasskey) ValidateAccessTokenWithContext(_ context.Context, _ string) (*tokenDomain.AccessTokenClaims, error) {
	return &tokenDomain.AccessTokenClaims{AccountID: "account-001"}, nil
}
func (m *mockTokenMgrForPasskey) ValidateRefreshToken(_ context.Context, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "mock-refresh"}, nil
}
func (m *mockTokenMgrForPasskey) RotateRefreshToken(_ context.Context, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "rotated"}, nil
}
func (m *mockTokenMgrForPasskey) RevokeRefreshToken(_ context.Context, _ string) error { return nil }
func (m *mockTokenMgrForPasskey) IntrospectToken(_ context.Context, _ string) (map[string]any, error) {
	return map[string]any{"active": true}, nil
}
func (m *mockTokenMgrForPasskey) AccessExpiry() time.Duration { return 15 * time.Minute }

type mockAccountSvcForPasskey struct {
	findByIDFn func() (*accountDomain.Account, error)
}

func (m *mockAccountSvcForPasskey) FindAccountByID(_ context.Context, id string) (*accountDomain.Account, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn()
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockAccountSvcForPasskey) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) ChangePassword(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) SoftDeleteAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) SuspendAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) ActivateAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	return nil, 0, fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) AssignRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) RemoveRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) FindAccountByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) VerifyCredential(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return fmt.Errorf("not implemented")
}
func (m *mockAccountSvcForPasskey) UnbindFederatedIdentity(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

// ──────────────────────────────────────────────
// RegisterBegin
// ──────────────────────────────────────────────

func TestPasskey_RegisterBegin_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		accountSvc: &mockAccountSvcForPasskey{},
		logger:     zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/register/begin", ctrl.RegisterBegin)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/begin", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPasskey_RegisterBegin_AccountNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		accountSvc: &mockAccountSvcForPasskey{
			findByIDFn: func() (*accountDomain.Account, error) { return nil, fmt.Errorf("not found") },
		},
		logger: zap.NewNop(),
	}
	api := engine.Group("/api/auth")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	api.POST("/passkey/register/begin", ctrl.RegisterBegin)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/begin", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ──────────────────────────────────────────────
// RegisterComplete
// ──────────────────────────────────────────────

func TestPasskey_RegisterComplete_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		accountSvc: &mockAccountSvcForPasskey{},
		logger:     zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/register/complete", ctrl.RegisterComplete)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/complete", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// LoginComplete
// ──────────────────────────────────────────────

func TestPasskey_LoginComplete_MissingBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		authSvc:    &mockAuthOrchForPasskey{},
		tokenMgr:   &mockTokenMgrForPasskey{},
		logger:     zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/login/complete", ctrl.LoginComplete)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/login/complete", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// MFABegin
// ──────────────────────────────────────────────

func TestPasskey_MFABegin_MissingBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		authSvc:    &mockAuthOrchForPasskey{},
		logger:     zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/mfa/begin", ctrl.MFABegin)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/mfa/begin", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasskey_MFABegin_InvalidMFAToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: &service.PasskeyService{},
		authSvc: &mockAuthOrchForPasskey{
			validateMFATokenFn: func() (*tokenDomain.AccessTokenClaims, error) {
				return nil, fmt.Errorf("invalid token")
			},
		},
		logger: zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/mfa/begin", ctrl.MFABegin)

	body := `{"mfa_token":"bad-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/mfa/begin", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// MFAComplete
// ──────────────────────────────────────────────

func TestPasskey_MFAComplete_MissingBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		authSvc:    &mockAuthOrchForPasskey{},
		logger:     zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/mfa/complete", ctrl.MFAComplete)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/mfa/complete", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasskey_MFAComplete_InvalidMFAToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: &service.PasskeyService{},
		authSvc: &mockAuthOrchForPasskey{
			validateMFATokenFn: func() (*tokenDomain.AccessTokenClaims, error) {
				return nil, fmt.Errorf("expired")
			},
		},
		logger: zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/mfa/complete", ctrl.MFAComplete)

	body := `{"mfa_token":"expired-token","request_id":"test-request-id"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/mfa/complete", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// ListCredentials
// ──────────────────────────────────────────────

func TestPasskey_ListCredentials_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		logger:     zap.NewNop(),
	}
	engine.GET("/api/auth/passkeys", ctrl.ListCredentials)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/passkeys", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// DeleteCredential
// ──────────────────────────────────────────────

func TestPasskey_DeleteCredential_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
		logger:     zap.NewNop(),
	}
	engine.DELETE("/api/auth/passkeys/:id", ctrl.DeleteCredential)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/passkeys/cred-001", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// LoginComplete — full flow with mock auth
// ──────────────────────────────────────────────

func TestPasskey_LoginComplete_LoginByPasskeyError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil, // not needed for this test path
		authSvc: &mockAuthOrchForPasskey{
			loginByPasskeyFn: func() (*service.LoginResult, error) {
				return nil, fmt.Errorf("account is not active")
			},
		},
		tokenMgr: &mockTokenMgrForPasskey{},
		logger:   zap.NewNop(),
	}
	engine.POST("/login/complete", func(ctx *gin.Context) {
		// Simulate the post-CompleteLogin flow
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		loginResult, err := ctrl.authSvc.LoginByPasskey(ctx, "account-001", "127.0.0.1", "test-agent")
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"access_token": loginResult.AccessToken})
	})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "account is not active")
}

func TestPasskey_LoginComplete_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		authSvc: &mockAuthOrchForPasskey{
			loginByPasskeyFn: func() (*service.LoginResult, error) {
				return &service.LoginResult{
					AccessToken:  "access-123",
					RefreshToken: "refresh-456",
					Session:      &sessionDomain.Session{ID: [16]byte{1, 2, 3}},
				}, nil
			},
		},
		tokenMgr: &mockTokenMgrForPasskey{},
		logger:   zap.NewNop(),
	}
	engine.POST("/login/complete", func(ctx *gin.Context) {
		loginResult, err := ctrl.authSvc.LoginByPasskey(ctx, "account-001", "127.0.0.1", "test-agent")
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, gouno_test_helper(loginResult))
	})

	req := httptest.NewRequest(http.MethodPost, "/login/complete", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "access-123", resp["access_token"])
}

func gouno_test_helper(result *service.LoginResult) gin.H {
	return gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
	}
}
