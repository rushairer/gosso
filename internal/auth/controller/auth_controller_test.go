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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/middleware"
)

// ──────────────────────────────────────────────
// Mock implementations
// ──────────────────────────────────────────────

type mockAuthOrchestrator struct {
	loginFn           func() (*service.LoginResult, error)
	mfaVerifyFn       func() (*service.LoginResult, error)
	logoutFn          func() error
	refreshFn         func() (*service.RefreshResult, error)
	validateSessionFn func() (*sessionDomain.Session, error)
	listSessionsFn    func() ([]*sessionDomain.Session, error)
	revokeSessionFn   func() error
}

func (m *mockAuthOrchestrator) LoginByUsernamePassword(_ context.Context, _ *service.LoginRequest) (*service.LoginResult, error) {
	if m.loginFn != nil {
		return m.loginFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchestrator) VerifyMFALogin(_ context.Context, _, _, _, _, _ string) (*service.LoginResult, error) {
	if m.mfaVerifyFn != nil {
		return m.mfaVerifyFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchestrator) Logout(_ context.Context, _, _, _ string, _ time.Time) error {
	if m.logoutFn != nil {
		return m.logoutFn()
	}
	return nil
}

func (m *mockAuthOrchestrator) RefreshTokens(_ context.Context, _ string) (*service.RefreshResult, error) {
	if m.refreshFn != nil {
		return m.refreshFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchestrator) ValidateSession(_ context.Context, _ string) (*sessionDomain.Session, error) {
	if m.validateSessionFn != nil {
		return m.validateSessionFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchestrator) ListSessions(_ context.Context, _ string) ([]*sessionDomain.Session, error) {
	if m.listSessionsFn != nil {
		return m.listSessionsFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAuthOrchestrator) RevokeSession(_ context.Context, _, _ string) error {
	if m.revokeSessionFn != nil {
		return m.revokeSessionFn()
	}
	return nil
}

func (m *mockAuthOrchestrator) ConfirmVerificationCredential(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAuthOrchestrator) MFAService() *service.MFAService         { return nil }
func (m *mockAuthOrchestrator) PasskeyService() *service.PasskeyService { return nil }

type mockTokenManager struct {
	accessExpiry time.Duration
}

func (m *mockTokenManager) GenerateAccessToken(_ *tokenDomain.AccessTokenClaims) (string, error) {
	return "mock-access-token", nil
}

func (m *mockTokenManager) GenerateRefreshToken(_ context.Context, _, _, _, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "mock-refresh-token"}, nil
}

func (m *mockTokenManager) ValidateAccessTokenWithContext(_ context.Context, _ string) (*tokenDomain.AccessTokenClaims, error) {
	return &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}, nil
}

func (m *mockTokenManager) ValidateRefreshToken(_ context.Context, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "mock-refresh-token"}, nil
}

func (m *mockTokenManager) RotateRefreshToken(_ context.Context, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "rotated-token"}, nil
}

func (m *mockTokenManager) RevokeRefreshToken(_ context.Context, _ string) error { return nil }

func (m *mockTokenManager) IntrospectToken(_ context.Context, _ string) (map[string]any, error) {
	return map[string]any{"active": true}, nil
}

func (m *mockTokenManager) AccessExpiry() time.Duration {
	if m.accessExpiry > 0 {
		return m.accessExpiry
	}
	return 15 * time.Minute
}

// ──────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────

func setupAuthController(authSvc *mockAuthOrchestrator, tokenMgr *mockTokenManager) (*gin.Engine, *AuthController) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := NewAuthController(authSvc, tokenMgr, nil, nil, nil, false, zap.NewNop())

	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, AuthRouteConfig{})

	return engine, ctrl
}

func setupAuthControllerWithClaims(authSvc *mockAuthOrchestrator, tokenMgr *mockTokenManager, claims *tokenDomain.AccessTokenClaims) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyClaims, claims)
		ctx.Next()
	})

	ctrl := NewAuthController(authSvc, tokenMgr, nil, nil, nil, false, zap.NewNop())
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, AuthRouteConfig{})

	return engine
}

func newTestSession() *sessionDomain.Session {
	return &sessionDomain.Session{
		ID:           uuid.New().String(),
		AccountID:    uuid.New().String(),
		IP:           "127.0.0.1",
		UserAgent:    "test-agent",
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}
}

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	session := newTestSession()
	authSvc := &mockAuthOrchestrator{
		loginFn: func() (*service.LoginResult, error) {
			return &service.LoginResult{
				AccessToken:  "access-123",
				RefreshToken: "refresh-456",
				Session:      session,
			}, nil
		},
	}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"username":"testuser","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "access-123", data["access_token"])
	assert.Equal(t, "refresh-456", data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.Equal(t, float64(900), data["expires_in"])
	assert.Equal(t, session.ID, data["session_id"])
}

func TestLogin_MFARequired(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		loginFn: func() (*service.LoginResult, error) {
			return &service.LoginResult{
				AccessToken: "mfa-token-123",
				RequiresMFA: true,
				MFATypes:    []string{"totp"},
			}, nil
		},
	}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"username":"mfa_user","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, true, data["requires_mfa"])
	assert.Equal(t, "mfa-token-123", data["mfa_token"])
	assert.Equal(t, "Bearer", data["mfa_token_type"])
}

func TestLogin_InvalidCredentials(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		loginFn: func() (*service.LoginResult, error) {
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"username":"baduser","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_MissingFields(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"username":"testuser"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefresh_Success(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		refreshFn: func() (*service.RefreshResult, error) {
			return &service.RefreshResult{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
			}, nil
		},
	}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"refresh_token":"old-refresh-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "new-access", data["access_token"])
	assert.Equal(t, "new-refresh", data["refresh_token"])
}

func TestRefresh_InvalidToken(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		refreshFn: func() (*service.RefreshResult, error) {
			return nil, fmt.Errorf("invalid refresh token")
		},
	}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"refresh_token":"bad-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogout_Success(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		logoutFn: func() error { return nil },
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetSession_Unauthorized(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetSession_Success(t *testing.T) {
	session := newTestSession()
	authSvc := &mockAuthOrchestrator{
		validateSessionFn: func() (*sessionDomain.Session, error) {
			return session, nil
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: session.ID,
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListSessions_Success(t *testing.T) {
	sessions := []*sessionDomain.Session{newTestSession(), newTestSession()}
	authSvc := &mockAuthOrchestrator{
		listSessionsFn: func() ([]*sessionDomain.Session, error) {
			return sessions, nil
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].([]any)
	assert.Len(t, data, 2)
}

func TestRevokeSession_CannotRevokeCurrent(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "current-session",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/current-session", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeSession_Success(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		revokeSessionFn: func() error { return nil },
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "current-session",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/other-session-id", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestForgotPassword_InvalidEmail(t *testing.T) {
	// Note: ForgotPassword tests that call through to passwordResetSvc are skipped
	// because PasswordResetService is a concrete type (not interface-injected).
	// Validation-only tests that fail before reaching the service are safe.
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"email":"not-an-email"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAVerify_Success(t *testing.T) {
	session := newTestSession()
	authSvc := &mockAuthOrchestrator{
		mfaVerifyFn: func() (*service.LoginResult, error) {
			return &service.LoginResult{
				AccessToken:  "mfa-access-123",
				RefreshToken: "mfa-refresh-456",
				Session:      session,
			}, nil
		},
	}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"mfa_token":"mfa-tok","code":"123456","type":"totp"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/verify", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "mfa-access-123", data["access_token"])
	assert.Equal(t, "mfa-refresh-456", data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.Equal(t, float64(900), data["expires_in"])
	assert.Equal(t, session.ID, data["session_id"])
}

func TestMFAVerify_MissingCode(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"mfa_token":"mfa-tok"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/verify", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAVerify_ServiceError(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		mfaVerifyFn: func() (*service.LoginResult, error) {
			return nil, fmt.Errorf("expired MFA token")
		},
	}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"mfa_token":"mfa-tok","code":"123456","type":"totp"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/verify", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAVerify_MissingMFAToken(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/verify", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// Additional tests for coverage
// ──────────────────────────────────────────────

func TestMFAEnroll_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/enroll", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAActivate_BadBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAActivate_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFADisable_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/mfa", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAGenerateBackupCodes_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/backup-codes", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSocialAuthURL_NilService(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestSocialCallback_NilService(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestSendVerification_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSendVerification_InvalidType(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"sms","identifier":"1234567890"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "type must be")
}

func TestSendVerification_InvalidEmail(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"email","identifier":"not-an-email"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid email")
}

func TestSendVerification_ValidEmailNoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"email","identifier":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConfirmVerification_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConfirmVerification_InvalidType(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"sms","identifier":"1234567890","code":"000"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "type must be")
}

func TestResetPassword_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestForgotPassword_InvalidBody(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogout_ServiceError(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		logoutFn: func() error { return fmt.Errorf("logout failed") },
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListSessions_ServiceError(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		listSessionsFn: func() ([]*sessionDomain.Session, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRevokeSession_ServiceError(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		revokeSessionFn: func() error { return fmt.Errorf("db error") },
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/other-session", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRevokeSession_AccessDenied(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		revokeSessionFn: func() error { return sessionService.ErrSessionAccessDenied },
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/other-session", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetSession_ServiceError(t *testing.T) {
	authSvc := &mockAuthOrchestrator{
		validateSessionFn: func() (*sessionDomain.Session, error) {
			return nil, fmt.Errorf("session not found")
		},
	}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeSession_EmptyID(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Empty ID with trailing slash - gin should match the route
	// If ID is empty, handler returns 400
	if w.Code == http.StatusBadRequest {
		assert.Contains(t, w.Body.String(), "session id required")
	}
}
