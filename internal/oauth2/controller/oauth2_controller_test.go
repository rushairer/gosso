package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/middleware"
)

// setupTestRedis creates a miniredis-backed Redis client for testing.
func setupTestRedis(t *testing.T) *cache.RedisClient {
	t.Helper()
	mr := miniredis.RunT(t)
	client, err := cache.NewRedisClient("redis://"+mr.Addr(), 10, 5*time.Second, zap.NewNop())
	require.NoError(t, err)
	return client
}

// ──────────────────────────────────────────────
// Mocks
// ──────────────────────────────────────────────

type mockOAuth2ClientSvcForOAuth2 struct {
	findByIDFn func() (*oauth2Domain.OAuth2Client, error)
}

func (m *mockOAuth2ClientSvcForOAuth2) RegisterClient(_ context.Context, _ *oauth2Service.RegisterClientRequest) (*oauth2Domain.OAuth2Client, string, error) {
	return nil, "", fmt.Errorf("not implemented")
}

func (m *mockOAuth2ClientSvcForOAuth2) FindByClientID(_ context.Context, _ string) (*oauth2Domain.OAuth2Client, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockOAuth2ClientSvcForOAuth2) FindByAccountID(_ context.Context, _ string) ([]*oauth2Domain.OAuth2Client, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockOAuth2ClientSvcForOAuth2) UpdateClient(_ context.Context, _ *oauth2Domain.OAuth2Client) error {
	return nil
}

func (m *mockOAuth2ClientSvcForOAuth2) DeleteClient(_ context.Context, _, _ string) error {
	return nil
}

type mockTokenMgr struct {
	generateAccessFn  func() (string, error)
	generateRefreshFn func() (*tokenDomain.RefreshToken, error)
	rotateRefreshFn   func() (*tokenDomain.RefreshToken, error)
	revokeFn          func() error
	introspectFn      func() (map[string]any, error)
	validateRefreshFn func() (*tokenDomain.RefreshToken, error)
	validateAccessFn  func() (*tokenDomain.AccessTokenClaims, error)
}

func (m *mockTokenMgr) GenerateAccessToken(_ *tokenDomain.AccessTokenClaims) (string, error) {
	if m.generateAccessFn != nil {
		return m.generateAccessFn()
	}
	return "mock-access-token", nil
}

func (m *mockTokenMgr) GenerateRefreshToken(_ context.Context, _, _, _, _ string) (*tokenDomain.RefreshToken, error) {
	if m.generateRefreshFn != nil {
		return m.generateRefreshFn()
	}
	return &tokenDomain.RefreshToken{Token: "mock-refresh"}, nil
}

func (m *mockTokenMgr) RotateRefreshToken(_ context.Context, _ string) (*tokenDomain.RefreshToken, error) {
	if m.rotateRefreshFn != nil {
		return m.rotateRefreshFn()
	}
	return &tokenDomain.RefreshToken{Token: "rotated-refresh"}, nil
}

func (m *mockTokenMgr) RevokeRefreshToken(_ context.Context, _ string) error {
	if m.revokeFn != nil {
		return m.revokeFn()
	}
	return nil
}

func (m *mockTokenMgr) RevokeAccessToken(_ context.Context, _ string, _ time.Time) error {
	return nil
}

func (m *mockTokenMgr) IntrospectToken(_ context.Context, _ string) (map[string]any, error) {
	if m.introspectFn != nil {
		return m.introspectFn()
	}
	return map[string]any{"active": true}, nil
}

func (m *mockTokenMgr) AccessExpiry() time.Duration { return 15 * time.Minute }

func (m *mockTokenMgr) ValidateRefreshToken(_ context.Context, _ string) (*tokenDomain.RefreshToken, error) {
	if m.validateRefreshFn != nil {
		return m.validateRefreshFn()
	}
	return &tokenDomain.RefreshToken{Token: "valid-refresh", ClientID: "cid-test", AccountID: "account-001"}, nil
}

func (m *mockTokenMgr) ValidateAccessTokenWithContext(_ context.Context, _ string) (*tokenDomain.AccessTokenClaims, error) {
	if m.validateAccessFn != nil {
		return m.validateAccessFn()
	}
	return &tokenDomain.AccessTokenClaims{AccountID: "account-001"}, nil
}

type mockDeviceCodeMgr struct {
	createFn        func() (*oauth2Domain.DeviceCode, error)
	getFn           func() (*oauth2Domain.DeviceCode, error)
	getByUserCodeFn func() (*oauth2Domain.DeviceCode, error)
	authorizeFn     func() error
	denyFn          func() error
	checkPollFn     func() error
	markUsedFn      func() error
	claimFn         func() (*oauth2Domain.DeviceCode, error)
}

func (m *mockDeviceCodeMgr) CreateDeviceCode(_ context.Context, _ string, _ []string) (*oauth2Domain.DeviceCode, error) {
	if m.createFn != nil {
		return m.createFn()
	}
	return &oauth2Domain.DeviceCode{
		DeviceCode: "test-device-code",
		UserCode:   "ABCD-EFGH",
		ClientID:   "cid-test",
		Scopes:     []string{"openid"},
		Status:     oauth2Domain.DeviceCodeStatusPending,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		Interval:   5,
	}, nil
}

func (m *mockDeviceCodeMgr) GetDeviceCode(_ context.Context, _ string) (*oauth2Domain.DeviceCode, error) {
	if m.getFn != nil {
		return m.getFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockDeviceCodeMgr) GetDeviceCodeByUserCode(_ context.Context, _ string) (*oauth2Domain.DeviceCode, error) {
	if m.getByUserCodeFn != nil {
		return m.getByUserCodeFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockDeviceCodeMgr) AuthorizeDeviceCode(_ context.Context, _, _ string) error {
	if m.authorizeFn != nil {
		return m.authorizeFn()
	}
	return nil
}

func (m *mockDeviceCodeMgr) DenyDeviceCode(_ context.Context, _ string) error {
	if m.denyFn != nil {
		return m.denyFn()
	}
	return nil
}

func (m *mockDeviceCodeMgr) CheckAndUpdatePollRate(_ context.Context, _ string) error {
	if m.checkPollFn != nil {
		return m.checkPollFn()
	}
	return nil
}

func (m *mockDeviceCodeMgr) MarkUsed(_ context.Context, _ string) error {
	if m.markUsedFn != nil {
		return m.markUsedFn()
	}
	return nil
}

func (m *mockDeviceCodeMgr) ClaimAuthorizedDeviceCode(_ context.Context, _ string, _ string) (*oauth2Domain.DeviceCode, error) {
	if m.claimFn != nil {
		return m.claimFn()
	}
	return nil, fmt.Errorf("not implemented")
}

// setupOAuth2Router builds a gin.Engine with the OAuth2 controller routes.
// Since authCodeSvc/consentSvc/idTokenSvc require Redis, we only test
// endpoints that rely on clientSvc and tokenSvc (mockable interfaces).
// ──────────────────────────────────────────────
// Mock AccountValidator
// ──────────────────────────────────────────────

type mockAccountValidatorAlwaysActive struct{}

func (m *mockAccountValidatorAlwaysActive) IsAccountActive(_ context.Context, _ string) bool {
	return true
}

type mockAuthCodeMgr struct {
	validateCodeFn func() (*oauth2Domain.AuthorizationCode, error)
	generateCodeFn func() (*oauth2Domain.AuthorizationCode, error)
}

func (m *mockAuthCodeMgr) ValidateCode(_ context.Context, _, _, _ string, _ *string) (*oauth2Domain.AuthorizationCode, error) {
	if m.validateCodeFn != nil {
		return m.validateCodeFn()
	}
	return &oauth2Domain.AuthorizationCode{
		Code:      "valid-code",
		ClientID:  "cid-test",
		AccountID: "account-001",
		Scopes:    []string{"profile"},
		AuthTime:  time.Now(),
	}, nil
}

func (m *mockAuthCodeMgr) GenerateCode(_ context.Context, _, _, _ string, _ []string, _, _, _ string) (*oauth2Domain.AuthorizationCode, error) {
	if m.generateCodeFn != nil {
		return m.generateCodeFn()
	}
	return &oauth2Domain.AuthorizationCode{
		Code:      "new-auth-code",
		ClientID:  "cid-test",
		AccountID: "account-001",
		Scopes:    []string{"openid"},
	}, nil
}

type mockConsentMgr struct {
	getConsentFn  func() (*oauth2Domain.Consent, error)
	saveConsentFn func() error
}

func (m *mockConsentMgr) GetConsent(_ context.Context, _, _ string) (*oauth2Domain.Consent, error) {
	if m.getConsentFn != nil {
		return m.getConsentFn()
	}
	return nil, nil
}

func (m *mockConsentMgr) SaveConsent(_ context.Context, _ *oauth2Domain.Consent) error {
	if m.saveConsentFn != nil {
		return m.saveConsentFn()
	}
	return nil
}

type mockIDTokenMgr struct {
	generateIDTokenFn func() (string, error)
}

func (m *mockIDTokenMgr) GenerateIDToken(_ context.Context, _, _ string, _ []string, _ string, _ time.Time, _ string) (string, error) {
	if m.generateIDTokenFn != nil {
		return m.generateIDTokenFn()
	}
	return "mock-id-token", nil
}

type mockAccountValidatorInactive struct{}

func (m *mockAccountValidatorInactive) IsAccountActive(_ context.Context, _ string) bool {
	return false
}

func setupOAuth2Router(clientSvc *mockOAuth2ClientSvcForOAuth2, tokenSvc *mockTokenMgr, deviceCodeMgr *mockDeviceCodeMgr) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &OAuth2Controller{
		clientSvc:        clientSvc,
		clientAuth:       &oauth2Service.ClientAuthenticator{},
		tokenSvc:         tokenSvc,
		deviceCodeSvc:    deviceCodeMgr,
		accountValidator: &mockAccountValidatorAlwaysActive{},
		issuer:           "https://sso.example.com",
		logger:           zap.NewNop(),
	}

	// Register token and revoke routes (no Redis dependency)
	// authCtx simulates JWTAuthMiddleware by injecting account_id into context
	authCtx := func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	}
	engine.POST("/oauth2/token", ctrl.Token)
	engine.POST("/oauth2/revoke", authCtx, ctrl.Revoke)
	engine.POST("/oauth2/introspect", ctrl.Introspect)
	engine.POST("/oauth2/device/code", ctrl.DeviceCodeRequest)

	return engine
}

func newConfidentialTestClient() *oauth2Domain.OAuth2Client {
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.MinCost)
	return &oauth2Domain.OAuth2Client{
		ID:               "client-uuid-001",
		AccountID:        "account-001",
		ClientID:         "cid-test",
		ClientSecretHash: string(hash),
		Name:             "Test App",
		RedirectURIs:     []string{"https://app.example.com/callback"},
		GrantTypes:       []string{"authorization_code", "client_credentials"},
		Scopes:           []string{"openid", "profile", "email"},
		IsConfidential:   true,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// ──────────────────────────────────────────────
// splitScope (pure function)
// ──────────────────────────────────────────────

func TestSplitScope_Empty(t *testing.T) {
	assert.Nil(t, splitScope(""))
}

func TestSplitScope_Single(t *testing.T) {
	assert.Equal(t, []string{"openid"}, splitScope("openid"))
}

func TestSplitScope_Multiple(t *testing.T) {
	assert.Equal(t, []string{"openid", "profile", "email"}, splitScope("openid profile email"))
}

func TestSplitScope_ExtraSpaces(t *testing.T) {
	result := splitScope("openid  profile ")
	assert.Equal(t, []string{"openid", "profile"}, result)
}

// ──────────────────────────────────────────────
// Token endpoint
// ──────────────────────────────────────────────

func TestToken_MissingGrantType(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := "code=abc"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

// ──────────────────────────────────────────────
// csrfTokenFromCookie (pure function)
// ──────────────────────────────────────────────

func TestCSRFTokenFromCookie_HostPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.AddCookie(&http.Cookie{Name: "__Host-csrf_token", Value: "host-token-123"})

	assert.Equal(t, "host-token-123", csrfTokenFromCookie(ctx))
}

func TestCSRFTokenFromCookie_Fallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.AddCookie(&http.Cookie{Name: "csrf_token", Value: "fallback-token-456"})

	assert.Equal(t, "fallback-token-456", csrfTokenFromCookie(ctx))
}

func TestCSRFTokenFromCookie_NoCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	assert.Equal(t, "", csrfTokenFromCookie(ctx))
}

// ──────────────────────────────────────────────
// NewOAuth2Controller
// ──────────────────────────────────────────────

func TestNewOAuth2Controller_Success(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)
	assert.NotNil(t, ctrl)
	assert.NotNil(t, ctrl.consentTmpl)
	assert.NotNil(t, ctrl.deviceTmpl)
	assert.Equal(t, "https://sso.example.com", ctrl.issuer)
}

// ──────────────────────────────────────────────
// authenticateRequest
// ──────────────────────────────────────────────

func TestAuthenticateRequest_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl, _ := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	accountID, ok := ctrl.authenticateRequest(ctx)
	assert.False(t, ok)
	assert.Equal(t, "", accountID)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// intersectScopes (pure function)
// ──────────────────────────────────────────────

func TestIntersectScopes_Empty(t *testing.T) {
	assert.Nil(t, intersectScopes(nil, nil))
	assert.Nil(t, intersectScopes([]string{}, nil))
	assert.Nil(t, intersectScopes(nil, []string{"openid"}))
}

func TestIntersectScopes_NoMatch(t *testing.T) {
	assert.Nil(t, intersectScopes([]string{"email"}, []string{"openid", "profile"}))
}

func TestIntersectScopes_PartialMatch(t *testing.T) {
	result := intersectScopes([]string{"openid", "email", "profile"}, []string{"openid", "profile", "address"})
	assert.Equal(t, []string{"openid", "profile"}, result)
}

func TestIntersectScopes_FullMatch(t *testing.T) {
	result := intersectScopes([]string{"openid", "profile"}, []string{"openid", "profile", "email"})
	assert.Equal(t, []string{"openid", "profile"}, result)
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := "grant_type=password"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported_grant_type")
}

func TestToken_InvalidJSON(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// Token — client_credentials grant
// ──────────────────────────────────────────────

func TestToken_ClientCredentials_Success(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=client_credentials&client_id=cid-test&client_secret=test-secret&scope=openid profile"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "mock-access-token", resp["access_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Equal(t, float64(900), resp["expires_in"])
}

func TestToken_ClientCredentials_MissingCredentials(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := "grant_type=client_credentials"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "client_id and client_secret required")
}

func TestToken_ClientCredentials_ClientNotFound(t *testing.T) {
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return nil, fmt.Errorf("not found") },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=client_credentials&client_id=bad&client_secret=secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestToken_ClientCredentials_PublicClientRejected(t *testing.T) {
	client := newConfidentialTestClient()
	client.IsConfidential = false
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=client_credentials&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

func TestToken_ClientCredentials_WrongSecret(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=client_credentials&client_id=cid-test&client_secret=wrong-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid client_secret")
}

func TestToken_ClientCredentials_GrantNotAllowed(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = []string{"authorization_code"} // no client_credentials
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=client_credentials&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

// ──────────────────────────────────────────────
// Token — refresh_token grant
// ──────────────────────────────────────────────

func TestToken_RefreshToken_Success(t *testing.T) {
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
				return &oauth2Domain.OAuth2Client{
					ID:             "client-uuid-001",
					AccountID:      "account-001",
					ClientID:       "cid-test",
					Name:           "Test App",
					GrantTypes:     []string{"refresh_token"},
					Scopes:         []string{"openid"},
					IsConfidential: false,
				}, nil
			},
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "mock-access-token", resp["access_token"])
	assert.Equal(t, "rotated-refresh", resp["refresh_token"])
}

func TestToken_RefreshToken_Invalid(t *testing.T) {
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{},
		&mockTokenMgr{
			validateRefreshFn: func() (*tokenDomain.RefreshToken, error) {
				return nil, fmt.Errorf("token expired")
			},
		},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=refresh_token&refresh_token=bad-token"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_grant")
}

// ──────────────────────────────────────────────
// Token — authorization_code grant
// ──────────────────────────────────────────────

func TestToken_AuthCode_ClientNotFound(t *testing.T) {
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return nil, fmt.Errorf("not found") },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=authorization_code&client_id=bad&code=abc"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestToken_AuthCode_ConfidentialMissingSecret(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&code=abc"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "client_secret required")
}

// ──────────────────────────────────────────────
// Revoke endpoint
// ──────────────────────────────────────────────

func TestRevoke_Success(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := `{"token":"some-refresh-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevoke_MissingToken(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevoke_DifferentAccount_ReturnsOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &OAuth2Controller{
		tokenSvc:         &mockTokenMgr{},
		accountValidator: &mockAccountValidatorAlwaysActive{},
		logger:           zap.NewNop(),
	}
	// Auth context with a different account ID than the token owner
	engine.POST("/oauth2/revoke", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "other-account")
		ctx.Next()
	}, ctrl.Revoke)

	body := `{"token":"some-refresh-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ──────────────────────────────────────────────
// Introspect endpoint
// ──────────────────────────────────────────────

func TestIntrospect_BasicAuth_Success(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			introspectFn: func() (map[string]any, error) {
				return map[string]any{"active": true, "client_id": "cid-test"}, nil
			},
		},
		&mockDeviceCodeMgr{},
	)

	body := `{"token":"some-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("cid-test", "test-secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["active"])
}

func TestIntrospect_NoAuth(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := `{"token":"some-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "client authentication required")
}

func TestIntrospect_ClientNotFound(t *testing.T) {
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return nil, fmt.Errorf("not found") },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := `{"token":"some-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("bad-client", "secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIntrospect_WrongSecret(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := `{"token":"some-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("cid-test", "wrong-secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIntrospect_TokenInactive(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			introspectFn: func() (map[string]any, error) { return map[string]any{"active": false}, nil },
		},
		&mockDeviceCodeMgr{},
	)

	body := `{"token":"expired-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("cid-test", "test-secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["active"])
}

func TestIntrospect_InfrastructureError(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			introspectFn: func() (map[string]any, error) { return nil, fmt.Errorf("blacklist unavailable") },
		},
		&mockDeviceCodeMgr{},
	)

	body := `{"token":"some-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("cid-test", "test-secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "server_error")
}

func TestIntrospect_MissingToken_Body(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("cid-test", "test-secret")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// redirectWithCode (pure function)
// ──────────────────────────────────────────────

func TestRedirectWithCode_WithState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	redirectWithCode(ctx, "https://app.example.com/callback", "auth-code-123", "my-state")

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "code=auth-code-123")
	assert.Contains(t, location, "state=my-state")
}

func TestRedirectWithCode_WithoutState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	ctx.Request, _ = http.NewRequest("GET", "/", nil)
	redirectWithCode(ctx, "https://app.example.com/callback", "auth-code-123", "")

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "code=auth-code-123")
	assert.NotContains(t, location, "state=")
}

// ──────────────────────────────────────────────
// Authorize endpoint (basic validation only)
// ──────────────────────────────────────────────

func TestAuthorize_UnsupportedResponseType(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &OAuth2Controller{
		clientSvc: &mockOAuth2ClientSvcForOAuth2{},
		logger:    zap.NewNop(),
	}
	engine.GET("/oauth2/authorize", ctrl.Authorize)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=token&client_id=abc", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported_response_type")
}

func TestAuthorize_InvalidClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &OAuth2Controller{
		clientSvc: &mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return nil, fmt.Errorf("not found") },
		},
		logger: zap.NewNop(),
	}
	engine.GET("/oauth2/authorize", ctrl.Authorize)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=bad", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
}

func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	client := newConfidentialTestClient()
	ctrl := &OAuth2Controller{
		clientSvc: &mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		logger: zap.NewNop(),
	}
	engine.GET("/oauth2/authorize", ctrl.Authorize)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=cid-test&redirect_uri=https://evil.com/callback", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_redirect_uri")
}

func TestAuthorize_Unauthorized_NoAccountID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	client := newConfidentialTestClient()
	ctrl := &OAuth2Controller{
		clientSvc: &mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		logger: zap.NewNop(),
	}
	engine.GET("/oauth2/authorize", ctrl.Authorize)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=cid-test&redirect_uri=https://app.example.com/callback", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ──────────────────────────────────────────────
// Device Code Request endpoint
// ──────────────────────────────────────────────

func TestDeviceCodeRequest_Success(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = append(client.GrantTypes, oauth2Domain.GrantTypeDeviceCode)
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := `client_id=cid-test&client_secret=test-secret&scope=openid+profile`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/device/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["device_code"])
	assert.NotEmpty(t, resp["user_code"])
	assert.Equal(t, "https://sso.example.com/oauth2/device", resp["verification_uri"])
	assert.NotEmpty(t, resp["verification_uri_complete"])
	assert.NotNil(t, resp["expires_in"])
	assert.NotNil(t, resp["interval"])
}

func TestDeviceCodeRequest_InvalidClient(t *testing.T) {
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return nil, fmt.Errorf("not found") },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := `client_id=bad-client`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/device/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
}

func TestDeviceCodeRequest_GrantNotAllowed(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{},
	)

	body := `client_id=cid-test`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/device/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

func TestDeviceCodeRequest_MissingClientID(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := ``
	req := httptest.NewRequest(http.MethodPost, "/oauth2/device/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

// ──────────────────────────────────────────────
// Token — device_code grant
// ──────────────────────────────────────────────

func TestToken_DeviceCode_AuthorizationPending(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = append(client.GrantTypes, oauth2Domain.GrantTypeDeviceCode)
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{
			getFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-123",
					ClientID:   "cid-test",
					Status:     oauth2Domain.DeviceCodeStatusPending,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
					Interval:   5,
				}, nil
			},
		},
	)

	body := "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=cid-test&client_secret=test-secret&device_code=dc-123"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "device code already consumed")
}

func TestToken_DeviceCode_AccessDenied(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = append(client.GrantTypes, oauth2Domain.GrantTypeDeviceCode)
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{
			getFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-123",
					ClientID:   "cid-test",
					Status:     oauth2Domain.DeviceCodeStatusDenied,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
					Interval:   5,
				}, nil
			},
		},
	)

	body := "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=cid-test&client_secret=test-secret&device_code=dc-123"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "device code already consumed")
}

func TestToken_DeviceCode_ExpiredToken(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = append(client.GrantTypes, oauth2Domain.GrantTypeDeviceCode)
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{
			getFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-123",
					ClientID:   "cid-test",
					Status:     oauth2Domain.DeviceCodeStatusPending,
					ExpiresAt:  time.Now().Add(-1 * time.Minute),
					Interval:   5,
				}, nil
			},
		},
	)

	body := "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=cid-test&client_secret=test-secret&device_code=dc-123"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "expired_token")
}

func TestToken_DeviceCode_SlowDown(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = append(client.GrantTypes, oauth2Domain.GrantTypeDeviceCode)
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{
			getFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-123",
					ClientID:   "cid-test",
					Status:     oauth2Domain.DeviceCodeStatusPending,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
					Interval:   5,
				}, nil
			},
			checkPollFn: func() error { return oauth2Domain.ErrSlowDown },
		},
	)

	body := "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=cid-test&client_secret=test-secret&device_code=dc-123"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "slow_down")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestToken_DeviceCode_Success(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = append(client.GrantTypes, oauth2Domain.GrantTypeDeviceCode)
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockDeviceCodeMgr{
			getFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-123",
					ClientID:   "cid-test",
					AccountID:  "account-001",
					Scopes:     []string{"openid", "profile"},
					Status:     oauth2Domain.DeviceCodeStatusAuthorized,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
					Interval:   5,
				}, nil
			},
			claimFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-123",
					ClientID:   "cid-test",
					AccountID:  "account-001",
					Scopes:     []string{"openid", "profile"},
					Status:     oauth2Domain.DeviceCodeStatusUsed,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				}, nil
			},
		},
	)

	body := "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=cid-test&client_secret=test-secret&device_code=dc-123"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "mock-access-token", resp["access_token"])
	assert.Equal(t, "mock-refresh", resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Equal(t, float64(900), resp["expires_in"])
}

func TestToken_DeviceCode_MissingDeviceCode(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{}, &mockDeviceCodeMgr{})

	body := "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=cid-test"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

// ──────────────────────────────────────────────
// authenticateRequest (continued)
// ──────────────────────────────────────────────

func TestAuthenticateRequest_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tokenSvc := &mockTokenMgr{
		validateAccessFn: func() (*tokenDomain.AccessTokenClaims, error) {
			return nil, fmt.Errorf("token expired")
		},
	}
	ctrl, _ := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		tokenSvc,
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.Header.Set("Authorization", "Bearer bad-token")

	accountID, ok := ctrl.authenticateRequest(ctx)
	assert.False(t, ok)
	assert.Equal(t, "", accountID)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthenticateRequest_ScopedToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tokenSvc := &mockTokenMgr{
		validateAccessFn: func() (*tokenDomain.AccessTokenClaims, error) {
			return &tokenDomain.AccessTokenClaims{AccountID: "account-001", Scope: "mfa:verify"}, nil
		},
	}
	ctrl, _ := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		tokenSvc,
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.Header.Set("Authorization", "Bearer scoped-token")

	accountID, ok := ctrl.authenticateRequest(ctx)
	assert.False(t, ok)
	assert.Equal(t, "", accountID)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuthenticateRequest_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl, _ := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.Header.Set("Authorization", "Bearer valid-token")

	accountID, ok := ctrl.authenticateRequest(ctx)
	assert.True(t, ok)
	assert.Equal(t, "account-001", accountID)
}

// ──────────────────────────────────────────────
// RegisterRoutes
// ──────────────────────────────────────────────

func TestOAuth2RegisterRoutes_WithRateLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl, _ := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)

	engine := gin.New()
	noop := func(ctx *gin.Context) { ctx.Next() }
	rg := engine.Group("/oauth2")
	ctrl.RegisterRoutes(rg, noop, noop, noop)

	routes := engine.Routes()
	pathSet := make(map[string]bool)
	for _, r := range routes {
		pathSet[r.Method+" "+r.Path] = true
	}

	assert.True(t, pathSet["GET /oauth2/authorize"])
	assert.True(t, pathSet["POST /oauth2/authorize"])
	assert.True(t, pathSet["POST /oauth2/token"])
	assert.True(t, pathSet["POST /oauth2/revoke"])
	assert.True(t, pathSet["POST /oauth2/introspect"])
	assert.True(t, pathSet["POST /oauth2/device/code"])
	assert.True(t, pathSet["GET /oauth2/device"])
	assert.True(t, pathSet["POST /oauth2/device"])
}

// ──────────────────────────────────────────────
// Authorize: PKCE / public client paths
// ──────────────────────────────────────────────

func TestAuthorize_InvalidCodeChallengeMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	client := newConfidentialTestClient()
	clientSvc := &mockOAuth2ClientSvcForOAuth2{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
	}

	ctrl, _ := NewOAuth2Controller(
		clientSvc,
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)

	engine.GET("/oauth2/authorize", ctrl.Authorize)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=cid-test&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=plain", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "code_challenge_method must be S256")
}

func TestAuthorize_PKCERequiredForPublicClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	publicClient := &oauth2Domain.OAuth2Client{
		ID:             "pub-001",
		AccountID:      "account-001",
		ClientID:       "cid-public",
		Name:           "Public App",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		GrantTypes:     []string{"authorization_code"},
		Scopes:         []string{"openid"},
		IsConfidential: false,
	}

	clientSvc := &mockOAuth2ClientSvcForOAuth2{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return publicClient, nil
		},
	}

	ctrl, _ := NewOAuth2Controller(
		clientSvc,
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)

	engine.GET("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.Authorize(ctx)
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=cid-public&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&state=test-state", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "code_challenge is required for public clients")
}

// ──────────────────────────────────────────────
// DeviceUserPage
// ──────────────────────────────────────────────

func TestDeviceUserPage_EmptyUserCode(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, &mockDeviceCodeMgr{},
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/oauth2/device", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.DeviceUserPage(ctx)
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/device", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

func TestDeviceUserPage_UserCodeNotFound(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, &mockDeviceCodeMgr{
			getByUserCodeFn: func() (*oauth2Domain.DeviceCode, error) {
				return nil, fmt.Errorf("not found")
			},
		},
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/oauth2/device", ctrl.DeviceUserPage)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/device?user_code=XXXX-YYYY", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired code")
}

func TestDeviceUserPage_ExpiredCode(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, &mockDeviceCodeMgr{
			getByUserCodeFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-expired",
					UserCode:   "XXXX-YYYY",
					ClientID:   "cid-test",
					Status:     oauth2Domain.DeviceCodeStatusPending,
					ExpiresAt:  time.Now().Add(-10 * time.Minute),
				}, nil
			},
		},
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/oauth2/device", ctrl.DeviceUserPage)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/device?user_code=XXXX-YYYY", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "expired or is no longer valid")
}

func TestDeviceUserPage_ValidPendingCode(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
				return newConfidentialTestClient(), nil
			},
		},
		nil, nil,
		&mockTokenMgr{},
		nil, &mockDeviceCodeMgr{
			getByUserCodeFn: func() (*oauth2Domain.DeviceCode, error) {
				return &oauth2Domain.DeviceCode{
					DeviceCode: "dc-valid",
					UserCode:   "XXXX-YYYY",
					ClientID:   "cid-test",
					Scopes:     []string{"openid", "profile"},
					Status:     oauth2Domain.DeviceCodeStatusPending,
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				}, nil
			},
		},
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/oauth2/device", ctrl.DeviceUserPage)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/device?user_code=XXXX-YYYY", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Test App")
	assert.Contains(t, w.Body.String(), "openid")
}

// ──────────────────────────────────────────────
// DeviceUserSubmit
// ──────────────────────────────────────────────

func TestDeviceUserSubmit_MissingDeviceCode(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, &mockDeviceCodeMgr{},
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/device", ctrl.DeviceUserSubmit)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device", strings.NewReader("user_code=XXXX&csrf_token=test-csrf"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

func TestDeviceUserSubmit_Approved(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, &mockDeviceCodeMgr{
			authorizeFn: func() error { return nil },
		},
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/device", ctrl.DeviceUserSubmit)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device",
		strings.NewReader("device_code=dc-123&approved=true&csrf_token=test-csrf"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "granted")
}

func TestDeviceUserSubmit_Denied(t *testing.T) {
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, &mockDeviceCodeMgr{
			denyFn: func() error { return nil },
		},
		&mockAccountValidatorAlwaysActive{},
		nil, nil,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/device", ctrl.DeviceUserSubmit)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/device",
		strings.NewReader("device_code=dc-123&approved=false&csrf_token=test-csrf"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "denied")
}

// ──────────────────────────────────────────────
// SubmitConsent
// ──────────────────────────────────────────────

func TestSubmitConsent_MissingFields(t *testing.T) {
	redisClient := setupTestRedis(t)
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{},
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader("state=test&consent_id=test-consent"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

func TestSubmitConsent_NotApproved(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
				return client, nil
			},
		},
		nil, nil,
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	body := "client_id=cid-test&redirect_uri=https://app.example.com/callback&scope=openid&state=abc&consent_id=test-consent"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "error=access_denied")
	assert.Contains(t, w.Header().Get("Location"), "state=abc")
}

// ──────────────────────────────────────────────
// Helper: token router with auth code and id token support
// ──────────────────────────────────────────────

func setupAuthCodeRouter(
	clientSvc *mockOAuth2ClientSvcForOAuth2,
	tokenSvc *mockTokenMgr,
	authCodeSvc AuthCodeManager,
	idTokenSvc IDTokenManager,
	accountValidator AccountValidator,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &OAuth2Controller{
		clientSvc:        clientSvc,
		clientAuth:       &oauth2Service.ClientAuthenticator{},
		tokenSvc:         tokenSvc,
		authCodeSvc:      authCodeSvc,
		idTokenSvc:       idTokenSvc,
		accountValidator: accountValidator,
		issuer:           "https://sso.example.com",
		logger:           zap.NewNop(),
	}
	engine.POST("/oauth2/token", ctrl.Token)
	return engine
}

// ──────────────────────────────────────────────
// Token — authorization_code grant (expanded)
// ──────────────────────────────────────────────

func TestToken_AuthCode_Success(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=auth-code-123&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "mock-access-token", resp["access_token"])
	assert.Equal(t, "mock-refresh", resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Equal(t, float64(900), resp["expires_in"])
	assert.Nil(t, resp["id_token"], "should not include id_token without openid scope")
}

func TestToken_AuthCode_SuccessWithOpenID(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{
			validateCodeFn: func() (*oauth2Domain.AuthorizationCode, error) {
				return &oauth2Domain.AuthorizationCode{
					Code:      "valid-code",
					ClientID:  "cid-test",
					AccountID: "account-001",
					Scopes:    []string{"openid", "profile"},
					AuthTime:  time.Now(),
				}, nil
			},
		},
		&mockIDTokenMgr{},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=auth-code-123&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "mock-access-token", resp["access_token"])
	assert.Equal(t, "mock-refresh", resp["refresh_token"])
	assert.Equal(t, "mock-id-token", resp["id_token"])
}

func TestToken_AuthCode_GrantNotAllowed(t *testing.T) {
	client := newConfidentialTestClient()
	client.GrantTypes = []string{"client_credentials"}
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=abc"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

func TestToken_AuthCode_InvalidSecret(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=wrong-secret&code=abc"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid client_secret")
}

func TestToken_AuthCode_PublicClientNoPKCE(t *testing.T) {
	publicClient := &oauth2Domain.OAuth2Client{
		ID:             "pub-001",
		ClientID:       "cid-public",
		Name:           "Public App",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		GrantTypes:     []string{"authorization_code"},
		Scopes:         []string{"openid"},
		IsConfidential: false,
	}
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return publicClient, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-public&code=abc&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "code_verifier required for public clients")
}

func TestToken_AuthCode_PublicClientWithPKCE(t *testing.T) {
	publicClient := &oauth2Domain.OAuth2Client{
		ID:             "pub-001",
		ClientID:       "cid-public",
		Name:           "Public App",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		GrantTypes:     []string{"authorization_code"},
		Scopes:         []string{"openid"},
		IsConfidential: false,
	}
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return publicClient, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-public&code=abc&redirect_uri=https://app.example.com/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestToken_AuthCode_InvalidCode(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{
			validateCodeFn: func() (*oauth2Domain.AuthorizationCode, error) {
				return nil, fmt.Errorf("authorization code not found")
			},
		},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=bad-code&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_grant")
}

func TestToken_AuthCode_AccountInactive(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorInactive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=abc&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "account is not active")
}

func TestToken_AuthCode_GenerateAccessTokenError(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			generateAccessFn: func() (string, error) {
				return "", fmt.Errorf("signing key unavailable")
			},
		},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=abc&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "server_error")
}

func TestToken_AuthCode_GenerateRefreshTokenError(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			generateRefreshFn: func() (*tokenDomain.RefreshToken, error) {
				return nil, fmt.Errorf("redis unavailable")
			},
		},
		&mockAuthCodeMgr{},
		nil,
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=abc&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "server_error")
}

func TestToken_AuthCode_IDTokenError(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupAuthCodeRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAuthCodeMgr{
			validateCodeFn: func() (*oauth2Domain.AuthorizationCode, error) {
				return &oauth2Domain.AuthorizationCode{
					Code:      "valid-code",
					ClientID:  "cid-test",
					AccountID: "account-001",
					Scopes:    []string{"openid", "profile"},
					AuthTime:  time.Now(),
				}, nil
			},
		},
		&mockIDTokenMgr{
			generateIDTokenFn: func() (string, error) {
				return "", fmt.Errorf("signing key error")
			},
		},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=authorization_code&client_id=cid-test&client_secret=test-secret&code=abc&redirect_uri=https://app.example.com/callback"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to generate id_token")
}

// ──────────────────────────────────────────────
// Token — refresh_token grant (expanded)
// ──────────────────────────────────────────────

func newRefreshTestClient() *oauth2Domain.OAuth2Client {
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.MinCost)
	return &oauth2Domain.OAuth2Client{
		ID:               "client-uuid-001",
		AccountID:        "account-001",
		ClientID:         "cid-test",
		ClientSecretHash: string(hash),
		Name:             "Test App",
		GrantTypes:       []string{"refresh_token"},
		Scopes:           []string{"openid", "profile"},
		IsConfidential:   true,
	}
}

func setupRefreshTokenRouter(
	clientSvc *mockOAuth2ClientSvcForOAuth2,
	tokenSvc *mockTokenMgr,
	accountValidator AccountValidator,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ctrl := &OAuth2Controller{
		clientSvc:        clientSvc,
		clientAuth:       &oauth2Service.ClientAuthenticator{},
		tokenSvc:         tokenSvc,
		accountValidator: accountValidator,
		issuer:           "https://sso.example.com",
		logger:           zap.NewNop(),
	}
	engine.POST("/oauth2/token", ctrl.Token)
	return engine
}

func TestToken_RefreshToken_ClientMismatch(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			validateRefreshFn: func() (*tokenDomain.RefreshToken, error) {
				return &tokenDomain.RefreshToken{
					Token:     "valid-refresh",
					ClientID:  "other-client",
					AccountID: "account-001",
					Scope:     "openid",
				}, nil
			},
		},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "client_id mismatch")
}

func TestToken_RefreshToken_ClientNotFound(t *testing.T) {
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return nil, fmt.Errorf("not found") },
		},
		&mockTokenMgr{},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "client not found")
}

func TestToken_RefreshToken_GrantNotAllowed(t *testing.T) {
	client := newRefreshTestClient()
	client.GrantTypes = []string{"authorization_code"}
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

func TestToken_RefreshToken_ConfidentialMissingSecret(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "client_secret required for confidential clients")
}

func TestToken_RefreshToken_ConfidentialWrongSecret(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=wrong"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid client_secret")
}

func TestToken_RefreshToken_AccountInactive(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
		&mockAccountValidatorInactive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "account is not active")
}

func TestToken_RefreshToken_IPMismatch(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			validateRefreshFn: func() (*tokenDomain.RefreshToken, error) {
				return &tokenDomain.RefreshToken{
					Token:     "valid-refresh",
					ClientID:  "cid-test",
					AccountID: "account-001",
					Scope:     "openid",
					IP:        "10.0.0.1",
				}, nil
			},
		},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "refresh token IP mismatch")
}

func TestToken_RefreshToken_ScopeExceeds(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			validateRefreshFn: func() (*tokenDomain.RefreshToken, error) {
				return &tokenDomain.RefreshToken{
					Token:     "valid-refresh",
					ClientID:  "cid-test",
					AccountID: "account-001",
					Scope:     "openid",
				}, nil
			},
		},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret&scope=openid profile email"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_scope")
}

func TestToken_RefreshToken_RotateError(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			rotateRefreshFn: func() (*tokenDomain.RefreshToken, error) {
				return nil, fmt.Errorf("token already consumed")
			},
		},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_grant")
}

func TestToken_RefreshToken_GenerateAccessTokenError(t *testing.T) {
	client := newRefreshTestClient()
	engine := setupRefreshTokenRouter(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{
			generateAccessFn: func() (string, error) {
				return "", fmt.Errorf("signing key unavailable")
			},
		},
		&mockAccountValidatorAlwaysActive{},
	)

	body := "grant_type=refresh_token&refresh_token=valid-refresh&client_id=cid-test&client_secret=test-secret"
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "server_error")
}

// ──────────────────────────────────────────────
// SubmitConsent (expanded)
// ──────────────────────────────────────────────

func TestSubmitConsent_Success(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockAuthCodeMgr{},
		&mockConsentMgr{},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	// Store consent state in Redis so the PKCE validation passes
	consentID := "test-consent"
	stateData, _ := json.Marshal(map[string]string{
		"code_challenge":        "",
		"code_challenge_method": "",
		"nonce":                 "",
	})
	require.NoError(t, redisClient.Set(context.Background(), "consent_state:"+consentID, string(stateData), 5*time.Minute))

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	body := "client_id=cid-test&redirect_uri=https://app.example.com/callback&scope=openid+profile&state=abc&approved=true&consent_id=" + consentID
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "code=new-auth-code")
	assert.Contains(t, location, "state=abc")
}

func TestSubmitConsent_ClientNotFound(t *testing.T) {
	redisClient := setupTestRedis(t)
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return nil, fmt.Errorf("not found") },
		},
		&mockAuthCodeMgr{},
		&mockConsentMgr{},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	// Store consent state in Redis so the PKCE validation passes
	consentID := "test-consent"
	stateData, _ := json.Marshal(map[string]string{
		"code_challenge":        "",
		"code_challenge_method": "",
		"nonce":                 "",
	})
	require.NoError(t, redisClient.Set(context.Background(), "consent_state:"+consentID, string(stateData), 5*time.Minute))

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	body := "client_id=bad&redirect_uri=https://app.example.com/callback&scope=openid&state=abc&approved=true&consent_id=" + consentID
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_client")
}

func TestSubmitConsent_InvalidRedirectURI(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockAuthCodeMgr{},
		&mockConsentMgr{},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	// Store consent state in Redis so the PKCE validation passes
	consentID := "test-consent"
	stateData, _ := json.Marshal(map[string]string{
		"code_challenge":        "",
		"code_challenge_method": "",
		"nonce":                 "",
	})
	require.NoError(t, redisClient.Set(context.Background(), "consent_state:"+consentID, string(stateData), 5*time.Minute))

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	body := "client_id=cid-test&redirect_uri=https://evil.com/callback&scope=openid&state=abc&approved=true&consent_id=" + consentID
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_redirect_uri")
}

func TestSubmitConsent_InvalidScope(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	client.Scopes = []string{"openid"}
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockAuthCodeMgr{},
		&mockConsentMgr{},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	// Store consent state in Redis so the PKCE validation passes
	consentID := "test-consent"
	stateData, _ := json.Marshal(map[string]string{
		"code_challenge":        "",
		"code_challenge_method": "",
		"nonce":                 "",
	})
	require.NoError(t, redisClient.Set(context.Background(), "consent_state:"+consentID, string(stateData), 5*time.Minute))

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	body := "client_id=cid-test&redirect_uri=https://app.example.com/callback&scope=invalid_scope&state=abc&approved=true&consent_id=" + consentID
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_scope")
}

func TestSubmitConsent_SaveConsentError(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockAuthCodeMgr{},
		&mockConsentMgr{
			saveConsentFn: func() error { return fmt.Errorf("database error") },
		},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	// Store consent state in Redis so the PKCE validation passes
	consentID := "test-consent"
	stateData, _ := json.Marshal(map[string]string{
		"code_challenge":        "",
		"code_challenge_method": "",
		"nonce":                 "",
	})
	require.NoError(t, redisClient.Set(context.Background(), "consent_state:"+consentID, string(stateData), 5*time.Minute))

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	body := "client_id=cid-test&redirect_uri=https://app.example.com/callback&scope=openid&state=abc&approved=true&consent_id=" + consentID
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "server_error")
}

func TestSubmitConsent_GenerateCodeError(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockAuthCodeMgr{
			generateCodeFn: func() (*oauth2Domain.AuthorizationCode, error) {
				return nil, fmt.Errorf("redis unavailable")
			},
		},
		&mockConsentMgr{},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	// Store consent state in Redis so the PKCE validation passes
	consentID := "test-consent-id"
	stateData, _ := json.Marshal(map[string]string{
		"code_challenge":        "",
		"code_challenge_method": "",
		"nonce":                 "",
	})
	require.NoError(t, redisClient.Set(context.Background(), "consent_state:"+consentID, string(stateData), 5*time.Minute))

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.SubmitConsent(ctx)
	})

	body := "client_id=cid-test&redirect_uri=https://app.example.com/callback&scope=openid&state=abc&approved=true&consent_id=" + consentID
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "server_error")
}

// ──────────────────────────────────────────────
// Authorize (expanded)
// ──────────────────────────────────────────────

func TestAuthorize_Success(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockAuthCodeMgr{},
		&mockConsentMgr{
			getConsentFn: func() (*oauth2Domain.Consent, error) {
				return &oauth2Domain.Consent{
					AccountID: "account-001",
					ClientID:  "cid-test",
					Scopes:    []string{"openid", "profile"},
				}, nil
			},
		},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.Authorize(ctx)
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=cid-test&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid+profile&state=my-state", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "code=new-auth-code")
	assert.Contains(t, location, "state=my-state")
}

func TestAuthorize_ShowsConsentPage(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		nil,
		&mockConsentMgr{},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.Authorize(ctx)
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=cid-test&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&state=my-state", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, w.Body.String(), "Test App")
}

func TestAuthorize_ConsentPageNoScopeOverlap(t *testing.T) {
	redisClient := setupTestRedis(t)
	client := newConfidentialTestClient()
	ctrl, err := NewOAuth2Controller(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		nil,
		&mockConsentMgr{
			getConsentFn: func() (*oauth2Domain.Consent, error) {
				return &oauth2Domain.Consent{
					AccountID: "account-001",
					ClientID:  "cid-test",
					Scopes:    []string{"email"},
				}, nil
			},
		},
		&mockTokenMgr{},
		nil, nil,
		&mockAccountValidatorAlwaysActive{},
		nil, redisClient,
		"https://sso.example.com",
		zap.NewNop(),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.GET("/oauth2/authorize", func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctrl.Authorize(ctx)
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=cid-test&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid+profile&state=my-state", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, w.Body.String(), "Test App")
}
