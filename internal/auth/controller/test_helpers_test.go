package controller

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	"github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
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
	verifyPasswordFn  func() error
	mfaSvc            *service.MFAService
}

func (m *mockAuthOrchestrator) LoginByUsernamePassword(_ context.Context, _ *service.LoginCommand) (*service.LoginResult, error) {
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

func (m *mockAuthOrchestrator) VerifyCurrentPassword(_ context.Context, _, _ string) error {
	if m.verifyPasswordFn != nil {
		return m.verifyPasswordFn()
	}
	return nil
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

func (m *mockTokenManager) RevokeAccessToken(_ context.Context, _ string, _ time.Time) error {
	return nil
}

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

func (m *mockCredentialRepoForController) FindByAccountAndTypes(_ context.Context, _ string, credTypes ...accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAccountAndTypeErr != nil {
		return nil, m.findByAccountAndTypeErr
	}
	var result []*accountDomain.Credential
	for _, ct := range credTypes {
		if m.findByAccountAndTypeResults != nil {
			result = append(result, m.findByAccountAndTypeResults[ct]...)
		}
	}
	return result, nil
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

func (m *mockCredentialRepoForController) FindPasswordCredentialTx(ctx context.Context, _ *sql.Tx, accountID string) (*accountDomain.Credential, error) {
	return m.FindPasswordCredential(ctx, accountID)
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

func (m *mockCredentialRepoForController) SoftDeleteCredentialsByType(_ context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType, _ time.Time) error {
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
	svc, err := service.NewMFAServiceWithConfig(credRepo, db, "test-issuer", zap.NewNop(), service.MFAServiceConfig{
		TOTPEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}, nil)
	require.NoError(t, err)
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

func (m *mockAccountServiceForSocial) FindByUsernameWithPasswordCredential(_ context.Context, _ string) (*accountDomain.Account, *accountDomain.Credential, error) {
	return nil, nil, fmt.Errorf("not implemented")
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

func (m *mockAccountServiceForSocial) SetOptions(_ *accountService.AccountServiceOptions) {}

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

func (m *mockFederatedIdentityRepoForSocial) FindByAccountIDTx(_ context.Context, _ *sql.Tx, _ string) ([]*accountDomain.FederatedIdentity, error) {
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
// Test helpers
// ──────────────────────────────────────────────

// noopRateLimiter is a no-op rate limit middleware for tests.
var noopRateLimiter gin.HandlerFunc = func(ctx *gin.Context) { ctx.Next() }

// testRouteConfig returns an AuthRouteConfig with no-op rate limiters for testing.
func testRouteConfig() AuthRouteConfig {
	return AuthRouteConfig{
		LoginLimit:    noopRateLimiter,
		MFALimit:      noopRateLimiter,
		PasswordLimit: noopRateLimiter,
		RefreshLimit:  noopRateLimiter,
		SocialLimit:   noopRateLimiter,
	}
}

func setupAuthController(authSvc *mockAuthOrchestrator, tokenMgr *mockTokenManager) (*gin.Engine, *AuthController) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := NewAuthController(authSvc, tokenMgr, nil, nil, nil, false, zap.NewNop())

	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, testRouteConfig())

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
	ctrl.RegisterRoutes(api, testRouteConfig())

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

// setupAuthControllerWithMFA creates a controller with a real MFAService backed by sqlmock.
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
	ctrl.RegisterRoutes(api, testRouteConfig())

	return engine
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
	ctrl.RegisterRoutes(api, testRouteConfig())

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
	ctrl.RegisterRoutes(api, testRouteConfig())

	return engine
}

// setupAuthControllerWithSocial creates a controller with a SocialLoginService.
func setupAuthControllerWithSocial(socialSvc *service.SocialLoginService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{accessExpiry: 15 * time.Minute}
	ctrl := NewAuthController(authSvc, tokenMgr, socialSvc, nil, nil, false, zap.NewNop())
	api := engine.Group("/api")
	ctrl.RegisterRoutes(api, testRouteConfig())
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
