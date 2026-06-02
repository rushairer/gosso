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
	"golang.org/x/crypto/bcrypt"

	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

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

func (m *mockOAuth2ClientSvcForOAuth2) DeleteClient(_ context.Context, _ string) error {
	return nil
}

type mockTokenMgr struct {
	generateAccessFn  func() (string, error)
	generateRefreshFn func() (*tokenDomain.RefreshToken, error)
	rotateRefreshFn   func() (*tokenDomain.RefreshToken, error)
	revokeFn          func() error
	introspectFn      func() (map[string]any, error)
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

func (m *mockTokenMgr) IntrospectToken(_ context.Context, _ string) (map[string]any, error) {
	if m.introspectFn != nil {
		return m.introspectFn()
	}
	return map[string]any{"active": true}, nil
}

func (m *mockTokenMgr) AccessExpiry() time.Duration { return 15 * time.Minute }

// setupOAuth2Router builds a gin.Engine with the OAuth2 controller routes.
// Since authCodeSvc/consentSvc/idTokenSvc require Redis, we only test
// endpoints that rely on clientSvc and tokenSvc (mockable interfaces).
func setupOAuth2Router(clientSvc *mockOAuth2ClientSvcForOAuth2, tokenSvc *mockTokenMgr) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := &OAuth2Controller{
		clientSvc: clientSvc,
		tokenSvc:  tokenSvc,
		logger:    zap.NewNop(),
	}

	// Register token and revoke routes (no Redis dependency)
	engine.POST("/oauth2/token", ctrl.Token)
	engine.POST("/oauth2/revoke", ctrl.Revoke)
	engine.POST("/oauth2/introspect", ctrl.Introspect)

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
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

	body := `{"code":"abc"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

	body := `{"grant_type":"password"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unsupported_grant_type")
}

func TestToken_InvalidJSON(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
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
	)

	body := `{"grant_type":"client_credentials","client_id":"cid-test","client_secret":"test-secret","scope":"openid profile"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

	body := `{"grant_type":"client_credentials"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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
	)

	body := `{"grant_type":"client_credentials","client_id":"bad","client_secret":"secret"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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
	)

	body := `{"grant_type":"client_credentials","client_id":"cid-test","client_secret":"test-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "confidential client")
}

func TestToken_ClientCredentials_WrongSecret(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
	)

	body := `{"grant_type":"client_credentials","client_id":"cid-test","client_secret":"wrong-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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
	)

	body := `{"grant_type":"client_credentials","client_id":"cid-test","client_secret":"test-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized_client")
}

// ──────────────────────────────────────────────
// Token — refresh_token grant
// ──────────────────────────────────────────────

func TestToken_RefreshToken_Success(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

	body := `{"grant_type":"refresh_token","refresh_token":"valid-refresh"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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
			rotateRefreshFn: func() (*tokenDomain.RefreshToken, error) {
				return nil, fmt.Errorf("token expired")
			},
		},
	)

	body := `{"grant_type":"refresh_token","refresh_token":"bad-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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
	)

	body := `{"grant_type":"authorization_code","client_id":"bad","code":"abc"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestToken_AuthCode_ConfidentialMissingSecret(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
	)

	body := `{"grant_type":"authorization_code","client_id":"cid-test","code":"abc"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "client_secret required")
}

// ──────────────────────────────────────────────
// Revoke endpoint
// ──────────────────────────────────────────────

func TestRevoke_Success(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

	body := `{"token":"some-refresh-token"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestRevoke_MissingToken(t *testing.T) {
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
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
		&mockTokenMgr{},
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
	engine := setupOAuth2Router(&mockOAuth2ClientSvcForOAuth2{}, &mockTokenMgr{})

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
			introspectFn: func() (map[string]any, error) { return nil, fmt.Errorf("invalid") },
		},
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

func TestIntrospect_MissingToken_Body(t *testing.T) {
	client := newConfidentialTestClient()
	engine := setupOAuth2Router(
		&mockOAuth2ClientSvcForOAuth2{
			findByIDFn: func() (*oauth2Domain.OAuth2Client, error) { return client, nil },
		},
		&mockTokenMgr{},
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
