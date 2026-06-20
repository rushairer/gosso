package controller

import (
	"bytes"
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

	"github.com/rushairer/gosso/internal/auth/service"
)

// ──────────────────────────────────────────────
// Login tests
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
				MFAToken:    "mfa-token-123",
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

// ──────────────────────────────────────────────
// Refresh tests
// ──────────────────────────────────────────────

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

// ──────────────────────────────────────────────
// MFAVerify tests
// ──────────────────────────────────────────────

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
// RegisterRoutes rate limiting + mfaMgmtHandlers
// ──────────────────────────────────────────────

func TestRegisterRoutes_WithRateLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	loginRateLimited := func(ctx *gin.Context) {
		ctx.Header("X-Login-Rate-Limited", "true")
		ctx.Next()
	}

	authSvc := &mockAuthOrchestrator{
		loginFn: func() (*service.LoginResult, error) {
			return &service.LoginResult{
				AccessToken: "test-token",
				Session:     newTestSession(),
			}, nil
		},
	}
	tokenMgr := &mockTokenManager{}

	ctrl := NewAuthController(authSvc, tokenMgr, nil, nil, nil, false, zap.NewNop())
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, AuthRouteConfig{
		LoginLimit:    loginRateLimited,
		RefreshLimit:  loginRateLimited,
		MFALimit:      loginRateLimited,
		SocialLimit:   loginRateLimited,
		VerifyLimit:   loginRateLimited,
		PasswordLimit: loginRateLimited,
	})

	body := `{"username":"test","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Login-Rate-Limited"))
}

func TestMfaMgmtHandlers_NonNil(t *testing.T) {
	handler := func(ctx *gin.Context) {}
	result := mfaMgmtHandlers(handler)
	assert.NotNil(t, result)
	assert.Len(t, result, 1)
}
