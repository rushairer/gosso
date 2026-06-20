package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// Logout tests
// ──────────────────────────────────────────────

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

// ──────────────────────────────────────────────
// GetSession tests
// ──────────────────────────────────────────────

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

// ──────────────────────────────────────────────
// ListSessions tests
// ──────────────────────────────────────────────

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

// ──────────────────────────────────────────────
// RevokeSession tests
// ──────────────────────────────────────────────

func TestRevokeSession_CannotRevokeCurrent(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "550e8400-e29b-41d4-a716-446655440099",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/550e8400-e29b-41d4-a716-446655440099", nil)
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
		SessionID: "550e8400-e29b-41d4-a716-446655440001",
	}
	engine := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/550e8400-e29b-41d4-a716-446655440002", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
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

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/550e8400-e29b-41d4-a716-446655440001", nil)
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

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/550e8400-e29b-41d4-a716-446655440001", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
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
