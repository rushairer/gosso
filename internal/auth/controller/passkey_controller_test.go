package controller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	authDomain "github.com/rushairer/gosso/internal/auth/domain"
	"github.com/rushairer/gosso/internal/auth/repository"
	"github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/middleware"
)

// ──────────────────────────────────────────────
// Mocks
// ──────────────────────────────────────────────

type mockAuthOrchForPasskey struct {
	loginByPasskeyFn          func() (*service.LoginResult, error)
	validateMFATokenFn        func() (*tokenDomain.AccessTokenClaims, error)
	markPasskeyMFAFn          func() error
	completePasskeyMFALoginFn func() (*service.LoginResult, error)
}

func (m *mockAuthOrchForPasskey) LoginByPasskey(_ context.Context, _, _, _ string) (*service.LoginResult, error) {
	if m.loginByPasskeyFn != nil {
		return m.loginByPasskeyFn()
	}
	return nil, fmt.Errorf("not implemented")
}

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

type mockAccountLookupForPasskey struct {
	err error
}

func (m *mockAccountLookupForPasskey) FindAccountByID(_ context.Context, _ string) (*accountDomain.Account, error) {
	return nil, m.err
}

// ──────────────────────────────────────────────
// mockWebAuthnCredRepo
// ──────────────────────────────────────────────

type mockWebAuthnCredRepo struct {
	findByAccountIDResults   []*authDomain.WebAuthnCredential
	findByAccountIDErr       error
	findByCredentialIDResult *authDomain.WebAuthnCredential
	findByCredentialIDErr    error
	softDeleteCredentialErr  error
}

func (m *mockWebAuthnCredRepo) CreateCredential(_ context.Context, _ *sql.Tx, _ *authDomain.WebAuthnCredential) error {
	return nil
}

func (m *mockWebAuthnCredRepo) FindByCredentialID(_ context.Context, credentialID string) (*authDomain.WebAuthnCredential, error) {
	if m.findByCredentialIDErr != nil {
		return nil, m.findByCredentialIDErr
	}
	return m.findByCredentialIDResult, nil
}

func (m *mockWebAuthnCredRepo) FindByAccountID(_ context.Context, accountID string) ([]*authDomain.WebAuthnCredential, error) {
	if m.findByAccountIDErr != nil {
		return nil, m.findByAccountIDErr
	}
	return m.findByAccountIDResults, nil
}

func (m *mockWebAuthnCredRepo) UpdateCredential(_ context.Context, _ *sql.Tx, _ *authDomain.WebAuthnCredential) error {
	return nil
}

func (m *mockWebAuthnCredRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return m.softDeleteCredentialErr
}

func (m *mockWebAuthnCredRepo) SoftDeleteByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

// newTestPasskeyServiceWithDB creates a PasskeyService with mocked webauthn repo and sqlmock DB.
func newTestPasskeyServiceWithDB(t *testing.T, credRepo repository.WebAuthnCredentialRepository, db *sql.DB) *service.PasskeyService {
	t.Helper()
	return service.NewPasskeyService(nil, credRepo, nil, db, nil, zap.NewNop())
}

// ──────────────────────────────────────────────
// RegisterBegin
// ──────────────────────────────────────────────

func TestPasskey_RegisterBegin_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &PasskeyController{
		passkeySvc: nil,
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

	passkeySvc := service.NewPasskeyService(nil, nil, nil, nil,
		&mockAccountLookupForPasskey{err: fmt.Errorf("account not found")},
		zap.NewNop(),
	)
	ctrl := &PasskeyController{
		passkeySvc: passkeySvc,
		logger:     zap.NewNop(),
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
		logger:     zap.NewNop(),
	}
	engine.POST("/api/auth/passkey/register/complete", ctrl.RegisterComplete)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/passkey/register/complete?request_id=test-req-id", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// ListCredentials — success and error paths
// ──────────────────────────────────────────────

func TestPasskey_ListCredentials_Success(t *testing.T) {
	now := time.Now()
	credRepo := &mockWebAuthnCredRepo{
		findByAccountIDResults: []*authDomain.WebAuthnCredential{
			{ID: "cred-001", AccountID: "account-001", Name: "My Laptop", CreatedAt: now, AttestationType: "none"},
			{ID: "cred-002", AccountID: "account-001", Name: "My Phone", CreatedAt: now, AttestationType: "packed"},
		},
	}
	passkeySvc := newTestPasskeyServiceWithDB(t, credRepo, nil)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &PasskeyController{passkeySvc: passkeySvc, logger: zap.NewNop()}

	api := engine.Group("/api/auth")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	api.GET("/passkeys", ctrl.ListCredentials)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/passkeys", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].([]any)
	assert.Len(t, data, 2)
	assert.Equal(t, "My Laptop", data[0].(map[string]any)["name"])
}

func TestPasskey_ListCredentials_ServiceError(t *testing.T) {
	credRepo := &mockWebAuthnCredRepo{
		findByAccountIDErr: fmt.Errorf("database connection lost"),
	}
	passkeySvc := newTestPasskeyServiceWithDB(t, credRepo, nil)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &PasskeyController{passkeySvc: passkeySvc, logger: zap.NewNop()}

	api := engine.Group("/api/auth")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	api.GET("/passkeys", ctrl.ListCredentials)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/passkeys", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ──────────────────────────────────────────────
// DeleteCredential — success, not found, ownership, empty ID
// ──────────────────────────────────────────────

// NOTE: The controller has a defensive empty-ID check ("credential id required"),
// but Gin's /:id parameter never delivers an empty segment — the router returns
// 404 before the handler runs. This code path is unreachable via normal routing.

func TestPasskey_DeleteCredential_NotFound(t *testing.T) {
	credRepo := &mockWebAuthnCredRepo{
		findByCredentialIDErr: fmt.Errorf("not found"),
	}
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	passkeySvc := newTestPasskeyServiceWithDB(t, credRepo, sqlDB)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &PasskeyController{passkeySvc: passkeySvc, logger: zap.NewNop()}

	api := engine.Group("/api/auth")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	api.DELETE("/passkeys/:id", ctrl.DeleteCredential)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/passkeys/00000000-0000-0000-0000-000000000999", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasskey_DeleteCredential_OwnershipMismatch(t *testing.T) {
	credRepo := &mockWebAuthnCredRepo{
		findByCredentialIDResult: &authDomain.WebAuthnCredential{
			ID: "cred-001", AccountID: "other-account",
		},
	}
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	passkeySvc := newTestPasskeyServiceWithDB(t, credRepo, sqlDB)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &PasskeyController{passkeySvc: passkeySvc, logger: zap.NewNop()}

	api := engine.Group("/api/auth")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	api.DELETE("/passkeys/:id", ctrl.DeleteCredential)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/passkeys/00000000-0000-0000-0000-000000000001", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPasskey_DeleteCredential_Success(t *testing.T) {
	credRepo := &mockWebAuthnCredRepo{
		findByCredentialIDResult: &authDomain.WebAuthnCredential{
			ID: "cred-001", AccountID: "account-001", Name: "My Laptop",
		},
	}
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	passkeySvc := newTestPasskeyServiceWithDB(t, credRepo, sqlDB)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &PasskeyController{passkeySvc: passkeySvc, logger: zap.NewNop()}

	api := engine.Group("/api/auth")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	api.DELETE("/passkeys/:id", ctrl.DeleteCredential)

	mock.ExpectBegin()
	mock.ExpectCommit()

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/passkeys/00000000-0000-0000-0000-000000000001", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPasskey_DeleteCredential_TxError(t *testing.T) {
	credRepo := &mockWebAuthnCredRepo{
		findByCredentialIDResult: &authDomain.WebAuthnCredential{
			ID: "cred-001", AccountID: "account-001", Name: "My Laptop",
		},
		softDeleteCredentialErr: fmt.Errorf("delete failed"),
	}
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	passkeySvc := newTestPasskeyServiceWithDB(t, credRepo, sqlDB)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &PasskeyController{passkeySvc: passkeySvc, logger: zap.NewNop()}

	api := engine.Group("/api/auth")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	api.DELETE("/passkeys/:id", ctrl.DeleteCredential)

	mock.ExpectBegin()
	mock.ExpectRollback()

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/passkeys/00000000-0000-0000-0000-000000000001", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
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

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/passkeys/00000000-0000-0000-0000-000000000001", nil)
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
				return nil, accountService.ErrAccountNotActive
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
					Session:      &sessionDomain.Session{ID: "test-session-id"},
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

// ──────────────────────────────────────────────
// NewPasskeyController
// ──────────────────────────────────────────────

func TestNewPasskeyController(t *testing.T) {
	authSvc := &mockAuthOrchForPasskey{}
	tokenMgr := &mockTokenMgrForPasskey{}
	ctrl := NewPasskeyController(nil, authSvc, tokenMgr, zap.NewNop())

	assert.NotNil(t, ctrl)
	assert.Nil(t, ctrl.passkeySvc)
	assert.NotNil(t, ctrl.logger)
}

// ──────────────────────────────────────────────
// RegisterRoutes — verify all routes are registered
// ──────────────────────────────────────────────

func TestPasskeyRegisterRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := NewPasskeyController(nil, &mockAuthOrchForPasskey{}, &mockTokenMgrForPasskey{}, zap.NewNop())

	jwtAuth := func(ctx *gin.Context) { ctx.Next() }
	rateLimit := func(ctx *gin.Context) { ctx.Next() }

	api := engine.Group("/api/auth")
	ctrl.RegisterRoutes(api, jwtAuth, rateLimit)

	// Each entry sends a request and expects a specific status.
	// We use input that fails early (bad auth, missing fields, nil passkeySvc)
	// so the handler never needs a real PasskeyService.
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{"register/begin JWT missing", http.MethodPost, "/api/auth/passkey/register/begin", "", http.StatusUnauthorized},
		{"register/complete JWT missing", http.MethodPost, "/api/auth/passkey/register/complete?request_id=test", "", http.StatusUnauthorized},
		{"passkeys list JWT missing", http.MethodGet, "/api/auth/passkeys", "", http.StatusUnauthorized},
		{"passkeys delete JWT missing", http.MethodDelete, "/api/auth/passkeys/00000000-0000-0000-0000-00000000abcd", "", http.StatusUnauthorized},
		{"mfa/begin nil passkeySvc", http.MethodPost, "/api/auth/passkey/mfa/begin", `{"mfa_token":"tok"}`, http.StatusServiceUnavailable},
		{"mfa/complete bad token", http.MethodPost, "/api/auth/passkey/mfa/complete", `{"mfa_token":"tok","request_id":"rid"}`, http.StatusUnauthorized},
		{"login/begin bad uuid", http.MethodPost, "/api/auth/passkey/login/begin", `{"account_id":"bad"}`, http.StatusBadRequest},
		{"login/complete missing field", http.MethodPost, "/api/auth/passkey/login/complete", "{}", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			assert.Equal(t, tt.want, w.Code)
		})
	}
}

func gouno_test_helper(result *service.LoginResult) gin.H {
	return gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    "Bearer",
	}
}
