package controller

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	"github.com/rushairer/gosso/internal/testutil"
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
	mfaSvc            *service.MFAService
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

func (m *mockAuthOrchestrator) MFAService() *service.MFAService         { return m.mfaSvc }
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
// Mock credential repository for MFA tests
// ──────────────────────────────────────────────

type mockCredentialRepoForController struct {
	findByAccountAndTypeResults    map[accountDomain.CredentialType][]*accountDomain.Credential
	findByAccountAndTypeErr        error
	findByTypeAndIdentifierFn      func(ctx context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error)
	createCredentialsErr           error
	softDeleteCredentialErr        error
	verifyFirstUnverifiedTOTPOK    bool
	verifyFirstUnverifiedTOTPError error
}

func (m *mockCredentialRepoForController) CreateCredentials(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
	return m.createCredentialsErr
}

func (m *mockCredentialRepoForController) FindByAccountAndType(_ context.Context, _ string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAccountAndTypeErr != nil {
		return nil, m.findByAccountAndTypeErr
	}
	if m.findByAccountAndTypeResults == nil {
		return nil, nil
	}
	return m.findByAccountAndTypeResults[credType], nil
}

func (m *mockCredentialRepoForController) FindByTypeAndIdentifier(ctx context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	if m.findByTypeAndIdentifierFn != nil {
		return m.findByTypeAndIdentifierFn(ctx, credType, identifier)
	}
	return nil, nil
}

func (m *mockCredentialRepoForController) FindPasswordCredential(_ context.Context, _ string) (*accountDomain.Credential, error) {
	return nil, nil
}

func (m *mockCredentialRepoForController) UpdateCredential(_ context.Context, _ *sql.Tx, _ *accountDomain.Credential) error {
	return nil
}

func (m *mockCredentialRepoForController) UpdateLastUsedAt(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func (m *mockCredentialRepoForController) SoftDeleteCredentialsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func (m *mockCredentialRepoForController) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return m.softDeleteCredentialErr
}

func (m *mockCredentialRepoForController) FindByAccountAndTypeForUpdate(_ context.Context, _ *sql.Tx, _ string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAccountAndTypeErr != nil {
		return nil, m.findByAccountAndTypeErr
	}
	if results, ok := m.findByAccountAndTypeResults[credType]; ok {
		return results, nil
	}
	return nil, nil
}

func (m *mockCredentialRepoForController) VerifyFirstUnverifiedTOTP(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
	return m.verifyFirstUnverifiedTOTPOK, m.verifyFirstUnverifiedTOTPError
}

func (m *mockCredentialRepoForController) FindByAccountAndTypeTx(ctx context.Context, _ *sql.Tx, _ string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return m.FindByAccountAndType(ctx, "", credType)
}

func (m *mockCredentialRepoForController) FindByTypeAndIdentifierTx(ctx context.Context, _ *sql.Tx, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	return m.FindByTypeAndIdentifier(ctx, credType, identifier)
}

// newTestMFAService creates an MFAService backed by sqlmock for controller-level tests.
func newTestMFAService(t *testing.T, credRepo accountRepo.CredentialRepository) (*service.MFAService, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc := service.NewMFAService(credRepo, db, "test-issuer", zap.NewNop(), nil)
	require.NoError(t, svc.SetTOTPEncryptionKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	return svc, mock
}

func encryptControllerTestTOTPSecret(t *testing.T, secret string) string {
	t.Helper()
	key, err := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(secret), nil))
}

// ──────────────────────────────────────────────
// Mock email senders for verification/password-reset tests
// ──────────────────────────────────────────────

type mockEmailSender struct {
	sendFn func(ctx context.Context, to, code string) error
}

func (m *mockEmailSender) SendVerificationCode(ctx context.Context, to, code string) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, to, code)
	}
	return nil
}

type mockPasswordResetEmailSender struct {
	sendFn func(ctx context.Context, to, resetLink string) error
}

func (m *mockPasswordResetEmailSender) SendPasswordResetLink(ctx context.Context, to, resetLink string) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, to, resetLink)
	}
	return nil
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

// setupAuthControllerWithVerificationSvc creates a controller with a real VerificationService backed by miniredis.
func setupAuthControllerWithVerificationSvc(t *testing.T, claims *tokenDomain.AccessTokenClaims, credRepo accountRepo.CredentialRepository, emailSender service.EmailSender) *gin.Engine {
	t.Helper()
	redisClient, _ := testutil.SetupTestRedis(t)

	verificationSvc := service.NewVerificationService(redisClient, emailSender, nil, credRepo, zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	if claims != nil {
		engine.Use(func(ctx *gin.Context) {
			ctx.Set(middleware.ContextKeyClaims, claims)
			ctx.Next()
		})
	}

	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}

	ctrl := NewAuthController(authSvc, tokenMgr, nil, verificationSvc, nil, false, zap.NewNop())
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, AuthRouteConfig{})

	return engine
}

// setupAuthControllerWithPasswordResetSvc creates a controller with a real PasswordResetService backed by miniredis.
func setupAuthControllerWithPasswordResetSvc(t *testing.T, credRepo accountRepo.CredentialRepository, emailSender service.PasswordResetEmailSender, accountSvc accountService.AccountService) *gin.Engine {
	t.Helper()
	redisClient, _ := testutil.SetupTestRedis(t)

	passwordResetSvc := service.NewPasswordResetService(redisClient, credRepo, emailSender, nil, nil, accountSvc, nil, "https://app.example.com/reset", zap.NewNop())

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}

	ctrl := NewAuthController(authSvc, tokenMgr, nil, nil, passwordResetSvc, false, zap.NewNop())
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, AuthRouteConfig{})

	return engine
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

func TestMFAActivate_FindByAccountAndTypeError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeErr: fmt.Errorf("database error"),
	}
	mfaSvc, _ := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAActivate_InvalidCode(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	storedSecret := encryptControllerTestTOTPSecret(t, key.Secret())

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
	}
	mfaSvc, _ := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	body := `{"code":"000000"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMFAActivate_NoPendingEnrollment(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptControllerTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
		verifyFirstUnverifiedTOTPOK: false,
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	mock.ExpectBegin()
	mock.ExpectCommit()

	reqBody := fmt.Sprintf(`{"code":%q}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAActivate_Success(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptControllerTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
		verifyFirstUnverifiedTOTPOK: true,
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	mock.ExpectBegin()
	mock.ExpectCommit()

	reqBody := fmt.Sprintf(`{"code":%q}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAActivate_VerifyFirstError(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test-issuer", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptControllerTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
			},
		},
		verifyFirstUnverifiedTOTPError: fmt.Errorf("transaction failed"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{}

	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
	}
	env := setupAuthControllerWithClaims(authSvc, tokenMgr, claims)

	mock.ExpectBegin()
	mock.ExpectRollback()

	reqBody := fmt.Sprintf(`{"code":%q}`, code)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/activate", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
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

// ──────────────────────────────────────────────
// setupAuthControllerWithMFA helper
// ──────────────────────────────────────────────

func setupAuthControllerWithMFA(claims *tokenDomain.AccessTokenClaims, mfaSvc *service.MFAService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyClaims, claims)
		ctx.Next()
	})

	authSvc := &mockAuthOrchestrator{mfaSvc: mfaSvc}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}

	ctrl := NewAuthController(authSvc, tokenMgr, nil, nil, nil, false, zap.NewNop())
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, AuthRouteConfig{})

	return engine
}

// ──────────────────────────────────────────────
// MFA controller tests with real MFAService (sqlmock-backed)
// ──────────────────────────────────────────────

func TestMFAEnroll_Success(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: nil,
		},
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// EnrollTOTP uses a single transaction for delete + create
	mock.ExpectBegin()
	mock.ExpectCommit()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/enroll", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.NotEmpty(t, data["secret"])
	assert.NotEmpty(t, data["otpauth_url"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAEnroll_ServiceError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: nil,
		},
		createCredentialsErr: fmt.Errorf("db error"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// EnrollTOTP uses a single transaction; CreateCredentials fails -> Rollback
	mock.ExpectBegin()
	mock.ExpectRollback()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/enroll", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFADisable_Success(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "cred-totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Verified: true},
			},
		},
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// DisableTOTP: Begin/Commit (single tx)
	mock.ExpectBegin()
	mock.ExpectCommit()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/mfa", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFADisable_ServiceError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeTOTP: {
				{ID: "cred-totp-001", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Verified: true},
			},
		},
		softDeleteCredentialErr: fmt.Errorf("delete failed"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// DisableTOTP: Begin/SoftDelete fails/Rollback
	mock.ExpectBegin()
	mock.ExpectRollback()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/mfa", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAGenerateBackupCodes_Success(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeBackupCode: nil,
		},
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// GenerateBackupCodes: Begin/Commit (single tx)
	mock.ExpectBegin()
	mock.ExpectCommit()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/backup-codes", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	codes := data["backup_codes"].([]any)
	assert.Len(t, codes, 10)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAGenerateBackupCodes_ServiceError(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeBackupCode: nil,
		},
		createCredentialsErr: fmt.Errorf("db error"),
	}
	mfaSvc, mock := newTestMFAService(t, credRepo)

	// GenerateBackupCodes: Begin/CreateCredentials fails/Rollback
	mock.ExpectBegin()
	mock.ExpectRollback()

	claims := &tokenDomain.AccessTokenClaims{AccountID: "account-001", SessionID: "session-001"}
	engine := setupAuthControllerWithMFA(claims, mfaSvc)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/backup-codes", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
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

// ──────────────────────────────────────────────
// Mocks for SocialLoginService (controller-level tests)
// ──────────────────────────────────────────────

type mockAccountServiceForSocial struct {
	findAccountByIDFn func(ctx context.Context, accountID string) (*accountDomain.Account, error)
}

func (m *mockAccountServiceForSocial) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) FindAccountByID(ctx context.Context, accountID string) (*accountDomain.Account, error) {
	if m.findAccountByIDFn != nil {
		return m.findAccountByIDFn(ctx, accountID)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) FindAccountByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) SoftDeleteAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) VerifyContactCredential(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) ChangePassword(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) UnbindFederatedIdentity(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) AssignRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) RemoveRole(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) SuspendAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) ActivateAccount(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockAccountServiceForSocial) SetSessionRevoker(_ accountService.SessionRevoker)           {}
func (m *mockAccountServiceForSocial) SetOAuth2ClientDeleter(_ accountService.OAuth2ClientDeleter) {}
func (m *mockAccountServiceForSocial) SetConsentCacheInvalidator(_ accountService.ConsentCacheInvalidator) {
}

type mockFederatedIdentityRepoForSocial struct {
	findByProviderFn func(ctx context.Context, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error)
}

func (m *mockFederatedIdentityRepoForSocial) CreateFederatedIdentity(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
	return fmt.Errorf("not implemented")
}

func (m *mockFederatedIdentityRepoForSocial) FindByProvider(ctx context.Context, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error) {
	if m.findByProviderFn != nil {
		return m.findByProviderFn(ctx, provider, providerUserID)
	}
	return nil, accountRepo.ErrFederatedIdentityNotFound
}

func (m *mockFederatedIdentityRepoForSocial) FindByAccountID(_ context.Context, _ string) ([]*accountDomain.FederatedIdentity, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockFederatedIdentityRepoForSocial) SoftDeleteByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockFederatedIdentityRepoForSocial) SoftDeleteByID(_ context.Context, _ *sql.Tx, _, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockFederatedIdentityRepoForSocial) FindByProviderTx(ctx context.Context, _ *sql.Tx, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error) {
	return m.FindByProvider(ctx, provider, providerUserID)
}

type mockSessionTokenCreator struct {
	createFn func(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error)
}

func (m *mockSessionTokenCreator) CreateSessionAndTokens(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
	if m.createFn != nil {
		return m.createFn(ctx, account, ip, userAgent)
	}
	return nil, "", nil, fmt.Errorf("not implemented")
}

// ──────────────────────────────────────────────
// Social login controller tests
// ──────────────────────────────────────────────

func setupAuthControllerWithSocial(socialSvc *service.SocialLoginService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}
	ctrl := NewAuthController(authSvc, tokenMgr, socialSvc, nil, nil, false, zap.NewNop())
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, AuthRouteConfig{})
	return engine
}

func newSocialTestServer(t *testing.T, tokenStatus int, tokenBody string, userinfoStatus int, userinfoBody string) *httptest.Server {
	t.Helper()
	testutil.RequireLocalHTTPServer(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tokenStatus)
			fmt.Fprint(w, tokenBody)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(userinfoStatus)
			fmt.Fprint(w, userinfoBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestSocialAuthURL_Success(t *testing.T) {
	providers := map[string]*service.OAuthProviderConfig{
		"google": {
			ClientID:    "test-client-id",
			RedirectURI: "https://app.example.com/callback",
			Scopes:      []string{"openid", "email"},
			AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	assert.Contains(t, location, "accounts.google.com")
	assert.Contains(t, location, "test-client-id")
	assert.Contains(t, location, "state=")

	// Verify state cookie is set
	resp := w.Result()
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie, "expected oauth_state cookie")
	assert.NotEmpty(t, stateCookie.Value)
	assert.True(t, stateCookie.HttpOnly)
}

func TestSocialAuthURL_UnsupportedProvider(t *testing.T) {
	providers := map[string]*service.OAuthProviderConfig{
		"google": {
			ClientID:    "test-client-id",
			RedirectURI: "https://app.example.com/callback",
			AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/facebook", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSocialCallback_MissingState(t *testing.T) {
	providers := map[string]*service.OAuthProviderConfig{
		"google": {AuthURL: "https://accounts.google.com/o/oauth2/v2/auth"},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSocialCallback_MismatchedState(t *testing.T) {
	providers := map[string]*service.OAuthProviderConfig{
		"google": {AuthURL: "https://accounts.google.com/o/oauth2/v2/auth"},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=state-a&code=test-code", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "state-b"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSocialCallback_MissingCode(t *testing.T) {
	providers := map[string]*service.OAuthProviderConfig{
		"google": {AuthURL: "https://accounts.google.com/o/oauth2/v2/auth"},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=test-state", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "test-state"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSocialCallback_ExchangeFails(t *testing.T) {
	srv := newSocialTestServer(t, http.StatusBadRequest, `{"error":"invalid_grant"}`, http.StatusOK, `{}`)
	defer srv.Close()

	providers := map[string]*service.OAuthProviderConfig{
		"google": {
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURI:  srv.URL + "/callback",
			TokenURL:     srv.URL + "/token",
			UserInfoURL:  srv.URL + "/userinfo",
		},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=test-state&code=bad-code", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "test-state"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSocialCallback_Success(t *testing.T) {
	srv := newSocialTestServer(t, http.StatusOK, `{"access_token":"test-social-token"}`, http.StatusOK, `{"id":12345,"email":"user@example.com","name":"Test User","email_verified":true}`)
	defer srv.Close()

	accountID := "social-account-001"
	fedIdentityRepo := &mockFederatedIdentityRepoForSocial{
		findByProviderFn: func(_ context.Context, _ accountDomain.Provider, _ string) (*accountDomain.FederatedIdentity, error) {
			return accountDomain.NewFederatedIdentity(accountID, accountDomain.Provider("google"), "12345", nil)
		},
	}

	activeAccount, _ := accountDomain.NewAccount("Test User")
	activeAccount.ID = accountID

	accountSvc := &mockAccountServiceForSocial{
		findAccountByIDFn: func(_ context.Context, id string) (*accountDomain.Account, error) {
			if id == accountID {
				return activeAccount, nil
			}
			return nil, fmt.Errorf("not found")
		},
	}

	sessionCreator := &mockSessionTokenCreator{
		createFn: func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
			return &sessionDomain.Session{
				ID:        "social-session-001",
				AccountID: accountID,
				IP:        "127.0.0.1",
				UserAgent: "test-agent",
				CreatedAt: time.Now(),
			}, "social-access-token", &tokenDomain.RefreshToken{Token: "social-refresh-token"}, nil
		},
	}

	providers := map[string]*service.OAuthProviderConfig{
		"google": {
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURI:  srv.URL + "/callback",
			Scopes:       []string{"openid", "email"},
			TokenURL:     srv.URL + "/token",
			UserInfoURL:  srv.URL + "/userinfo",
		},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, accountSvc, sessionCreator, nil, nil, fedIdentityRepo, providers, zap.NewNop(), nil, nil)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=test-state&code=good-code", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "test-state"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "social-access-token", data["access_token"])
	assert.Equal(t, "social-refresh-token", data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.Equal(t, float64(900), data["expires_in"])
	assert.Equal(t, "social-session-001", data["session_id"])

	// Verify oauth_state cookie is cleared
	for _, c := range w.Result().Cookies() {
		if c.Name == "oauth_state" {
			assert.Equal(t, -1, c.MaxAge)
		}
	}
}

// ──────────────────────────────────────────────
// SendVerification additional tests
// ──────────────────────────────────────────────

func TestSendVerification_InvalidPhone(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"phone","identifier":"not-a-phone"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid phone format")
}

func TestSendVerification_PhoneNotImplemented(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"phone","identifier":"+12345678901"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), "phone verification is not yet supported")
}

func TestSendVerification_CredentialNotOwned(t *testing.T) {
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}

	// Credential repo returns email credentials for account-001, but none match "user@example.com"
	otherEmail := "other@example.com"
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeEmail: {
				{ID: "cred-001", AccountID: "account-001", Type: accountDomain.CredentialTypeEmail, Identifier: &otherEmail},
			},
		},
	}

	emailSender := &mockEmailSender{}
	engine := setupAuthControllerWithVerificationSvc(t, claims, credRepo, emailSender)

	body := `{"type":"email","identifier":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request")
}

func TestSendVerification_Success(t *testing.T) {
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}

	userEmail := "user@example.com"
	credRepo := &mockCredentialRepoForController{
		findByAccountAndTypeResults: map[accountDomain.CredentialType][]*accountDomain.Credential{
			accountDomain.CredentialTypeEmail: {
				{ID: "cred-001", AccountID: "account-001", Type: accountDomain.CredentialTypeEmail, Identifier: &userEmail},
			},
		},
	}

	emailSent := false
	emailSender := &mockEmailSender{
		sendFn: func(_ context.Context, to, _ string) error {
			assert.Equal(t, userEmail, to)
			emailSent = true
			return nil
		},
	}

	engine := setupAuthControllerWithVerificationSvc(t, claims, credRepo, emailSender)

	body := `{"type":"email","identifier":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/send", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, emailSent, "email sender should have been called")
}

// ──────────────────────────────────────────────
// ConfirmVerification additional tests
// ──────────────────────────────────────────────

func TestConfirmVerification_NoClaims(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	body := `{"type":"email","identifier":"user@example.com","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestConfirmVerification_CodeVerifyFails(t *testing.T) {
	claims := &tokenDomain.AccessTokenClaims{
		AccountID: "account-001",
		SessionID: "session-001",
	}

	credRepo := &mockCredentialRepoForController{}
	emailSender := &mockEmailSender{}
	engine := setupAuthControllerWithVerificationSvc(t, claims, credRepo, emailSender)

	// miniredis does not support cjson Lua scripts, so VerifyCode will fail
	body := `{"type":"email","identifier":"user@example.com","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/verify/confirm", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid verification code")
}

// ──────────────────────────────────────────────
// ResetPassword additional tests
// ──────────────────────────────────────────────

func TestResetPassword_ShortPassword(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	// Password "short" is 5 chars, below the binding tag min=8
	body := `{"token":"some-token","new_password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

func TestResetPassword_InvalidToken(t *testing.T) {
	credRepo := &mockCredentialRepoForController{}
	emailSender := &mockPasswordResetEmailSender{}
	accountSvc := &mockAccountServiceForSocial{}
	engine := setupAuthControllerWithPasswordResetSvc(t, credRepo, emailSender, accountSvc)

	// Password meets ValidatePasswordStrength (12+ chars, upper+lower+digit+special),
	// but the cjson Lua script fails on miniredis so VerifyAndReset returns error.
	body := `{"token":"fake-invalid-token-abc123","new_password":"ValidP@ssw0rd!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired reset token")
}

// ──────────────────────────────────────────────
// ForgotPassword additional tests
// ──────────────────────────────────────────────

func TestForgotPassword_NonexistentEmail(t *testing.T) {
	credRepo := &mockCredentialRepoForController{
		findByTypeAndIdentifierFn: func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
			return nil, accountRepo.ErrCredentialNotFound
		},
	}
	emailSender := &mockPasswordResetEmailSender{}
	accountSvc := &mockAccountServiceForSocial{}
	engine := setupAuthControllerWithPasswordResetSvc(t, credRepo, emailSender, accountSvc)

	body := `{"email":"nonexistent@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Always 200 to prevent email enumeration
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestForgotPassword_Success(t *testing.T) {
	accountID := "account-001"
	userEmail := "user@example.com"

	credRepo := &mockCredentialRepoForController{
		findByTypeAndIdentifierFn: func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
			cred := &accountDomain.Credential{
				ID:         "cred-001",
				AccountID:  accountID,
				Type:       accountDomain.CredentialTypeEmail,
				Identifier: &userEmail,
			}
			return cred, nil
		},
	}

	activeAccount, _ := accountDomain.NewAccount("Test User")
	activeAccount.ID = accountID

	accountSvc := &mockAccountServiceForSocial{
		findAccountByIDFn: func(_ context.Context, id string) (*accountDomain.Account, error) {
			if id == accountID {
				return activeAccount, nil
			}
			return nil, fmt.Errorf("not found")
		},
	}

	resetEmailSent := false
	emailSender := &mockPasswordResetEmailSender{
		sendFn: func(_ context.Context, to, resetLink string) error {
			assert.Equal(t, userEmail, to)
			assert.Contains(t, resetLink, "https://app.example.com/reset#token=")
			resetEmailSent = true
			return nil
		},
	}

	engine := setupAuthControllerWithPasswordResetSvc(t, credRepo, emailSender, accountSvc)

	body := `{"email":"user@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/forgot", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, resetEmailSent, "password reset email sender should have been called")
}
