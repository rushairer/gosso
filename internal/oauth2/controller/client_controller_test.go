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

	authService "github.com/rushairer/gosso/internal/auth/service"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/middleware"
)

// ──────────────────────────────────────────────
// Mock OAuth2ClientService
// ──────────────────────────────────────────────

type mockOAuth2ClientService struct {
	registerFn        func() (*oauth2Domain.OAuth2Client, string, error)
	findByIDFn        func() (*oauth2Domain.OAuth2Client, error)
	findByAcctFn      func() ([]*oauth2Domain.OAuth2Client, error)
	updateFn          func() error
	updateByAccountFn func() (*oauth2Domain.OAuth2Client, error)
	deleteFn          func() error
	lastRegisterReq   *oauth2Service.RegisterClientRequest
	lastUpdateReq     *oauth2Service.UpdateClientRequest
}

func (m *mockOAuth2ClientService) RegisterClient(_ context.Context, req *oauth2Service.RegisterClientRequest) (*oauth2Domain.OAuth2Client, string, error) {
	m.lastRegisterReq = req
	if m.registerFn != nil {
		return m.registerFn()
	}
	return nil, "", fmt.Errorf("not implemented")
}

func (m *mockOAuth2ClientService) FindByClientID(_ context.Context, _ string) (*oauth2Domain.OAuth2Client, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockOAuth2ClientService) FindByAccountID(_ context.Context, _ string) ([]*oauth2Domain.OAuth2Client, error) {
	if m.findByAcctFn != nil {
		return m.findByAcctFn()
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockOAuth2ClientService) UpdateClient(_ context.Context, _ *oauth2Domain.OAuth2Client) error {
	if m.updateFn != nil {
		return m.updateFn()
	}
	return nil
}

func (m *mockOAuth2ClientService) UpdateClientByAccountID(_ context.Context, _, _ string, req *oauth2Service.UpdateClientRequest) (*oauth2Domain.OAuth2Client, error) {
	m.lastUpdateReq = req
	if m.updateByAccountFn != nil {
		return m.updateByAccountFn()
	}
	return nil, nil
}

func (m *mockOAuth2ClientService) DeleteClient(_ context.Context, _, _ string) error {
	if m.deleteFn != nil {
		return m.deleteFn()
	}
	return nil
}

// ──────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────

func setupClientController(clientSvc *mockOAuth2ClientService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := NewClientController(clientSvc, zap.NewNop())

	// Simulate JWT auth middleware that sets account_id
	api := engine.Group("/api")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Next()
	})
	ctrl.RegisterRoutes(api, func(ctx *gin.Context) { ctx.Next() })

	return engine
}

func setupAdminClientController(clientSvc *mockOAuth2ClientService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	ctrl := NewClientController(clientSvc, zap.NewNop())

	api := engine.Group("/api")
	api.Use(func(ctx *gin.Context) {
		ctx.Set(middleware.ContextKeyAccountID, "account-001")
		ctx.Set(middleware.ContextKeyClaims, &tokenDomain.AccessTokenClaims{
			Roles: []string{authService.RoleAdmin},
			Scope: "openid admin",
		})
		ctx.Next()
	})
	ctrl.RegisterRoutes(api, func(ctx *gin.Context) { ctx.Next() })

	return engine
}

func newTestClient(accountID string) *oauth2Domain.OAuth2Client {
	return &oauth2Domain.OAuth2Client{
		ID:             "client-uuid-001",
		AccountID:      accountID,
		ClientID:       "550e8400-e29b-41d4-a716-446655440000",
		Name:           "Test App",
		Description:    "A test app",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		GrantTypes:     []string{"authorization_code"},
		Scopes:         []string{"openid", "profile"},
		IsConfidential: true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

// ──────────────────────────────────────────────
// ClientController Tests
// ──────────────────────────────────────────────

func TestRegisterClient_Success(t *testing.T) {
	client := newTestClient("account-001")
	clientSvc := &mockOAuth2ClientService{
		registerFn: func() (*oauth2Domain.OAuth2Client, string, error) {
			return client, "secret-123", nil
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Test App","redirect_uris":["https://app.example.com/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth2/clients", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", data["client_id"])
	assert.Equal(t, "secret-123", data["client_secret"])
}

func TestRegisterClient_AdminCallerCanManageReservedScopes(t *testing.T) {
	client := newTestClient("account-001")
	client.Scopes = []string{"openid", "admin"}
	client.Metadata = map[string]any{oauth2Domain.ClientCapabilityMetadataKey: oauth2Domain.ClientCapabilityAdmin}
	clientSvc := &mockOAuth2ClientService{
		registerFn: func() (*oauth2Domain.OAuth2Client, string, error) {
			return client, "", nil
		},
	}
	engine := setupAdminClientController(clientSvc)

	body := `{"name":"Admin App","redirect_uris":["https://admin.example.com/callback"],"scopes":["openid","admin"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth2/clients", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	require.NotNil(t, clientSvc.lastRegisterReq)
	assert.True(t, clientSvc.lastRegisterReq.AllowReservedScopes)
}

func TestRegisterClient_InvalidBody(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{}
	engine := setupClientController(clientSvc)

	body := `{"description":"missing name"}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth2/clients", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListClients_Success(t *testing.T) {
	clients := []*oauth2Domain.OAuth2Client{
		newTestClient("account-001"),
		{ID: "client-2", AccountID: "account-001", ClientID: "cid-2", Name: "App 2"},
	}
	clientSvc := &mockOAuth2ClientService{
		findByAcctFn: func() ([]*oauth2Domain.OAuth2Client, error) {
			return clients, nil
		},
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].([]any)
	assert.Len(t, data, 2)
}

func TestListClients_Empty(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		findByAcctFn: func() ([]*oauth2Domain.OAuth2Client, error) {
			return nil, nil
		},
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].([]any)
	assert.Len(t, data, 0)
}

func TestGetClient_Success(t *testing.T) {
	client := newTestClient("account-001")
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetClient_NotFound(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetClient_IDORProtection(t *testing.T) {
	// Client belongs to a different account
	client := newTestClient("other-account-999")
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ──────────────────────────────────────────────
// Error-path tests for coverage
// ──────────────────────────────────────────────

func TestRegisterClient_InvalidRedirectScheme(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		registerFn: func() (*oauth2Domain.OAuth2Client, string, error) {
			return nil, "", &oauth2Service.ValidationError{Message: "redirect_uris must use http or https scheme without fragment: javascript:alert(1)"}
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Test","redirect_uris":["javascript:alert(1)"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth2/clients", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegisterClient_InvalidPostLogoutURI(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		registerFn: func() (*oauth2Domain.OAuth2Client, string, error) {
			return nil, "", &oauth2Service.ValidationError{Message: "post_logout_redirect_uris: redirect_uris must use http or https scheme without fragment: javascript:alert(1)"}
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Test","redirect_uris":["https://app.example.com/callback"],"post_logout_redirect_uris":["javascript:alert(1)"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth2/clients", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegisterClient_ServiceError(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		registerFn: func() (*oauth2Domain.OAuth2Client, string, error) {
			return nil, "", fmt.Errorf("db error")
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Test","redirect_uris":["https://app.example.com/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth2/clients", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListClients_ServiceError(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		findByAcctFn: func() ([]*oauth2Domain.OAuth2Client, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateClient_InvalidRedirectScheme(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		updateByAccountFn: func() (*oauth2Domain.OAuth2Client, error) {
			return nil, fmt.Errorf("redirect_uris must use http or https scheme without fragment: javascript:alert(1)")
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"redirect_uris":["javascript:alert(1)"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateClient_InvalidPostLogoutURI(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		updateByAccountFn: func() (*oauth2Domain.OAuth2Client, error) {
			return nil, fmt.Errorf("post_logout_redirect_uris: redirect_uris must use http or https scheme without fragment: javascript:alert(1)")
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"post_logout_redirect_uris":["javascript:alert(1)"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateClient_ServiceError(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		updateByAccountFn: func() (*oauth2Domain.OAuth2Client, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Updated App"}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteClient_ServiceError(t *testing.T) {
	client := newTestClient("account-001")
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
		deleteFn: func() error { return fmt.Errorf("db error") },
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateClient_Success(t *testing.T) {
	client := newTestClient("account-001")
	clientSvc := &mockOAuth2ClientService{
		updateByAccountFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Updated App","description":"Updated description"}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateClient_IDORProtection(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		updateByAccountFn: func() (*oauth2Domain.OAuth2Client, error) {
			return nil, oauth2Service.ErrClientAccessDenied
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Hacked Name"}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateClient_InvalidGrantType(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		updateByAccountFn: func() (*oauth2Domain.OAuth2Client, error) {
			return nil, fmt.Errorf("invalid grant_type: %q", "magic_unicorn")
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"grant_types":["authorization_code","magic_unicorn"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateClient_ValidGrantTypes(t *testing.T) {
	client := newTestClient("account-001")
	clientSvc := &mockOAuth2ClientService{
		updateByAccountFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"grant_types":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:device_code"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRegisterClient_InvalidGrantType(t *testing.T) {
	clientSvc := &mockOAuth2ClientService{
		registerFn: func() (*oauth2Domain.OAuth2Client, string, error) {
			return nil, "", &oauth2Service.ValidationError{Message: fmt.Sprintf("invalid grant_type: %q", "invalid_grant")}
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Test App","redirect_uris":["https://app.example.com/callback"],"grant_types":["authorization_code","invalid_grant"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/oauth2/clients", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteClient_Success(t *testing.T) {
	client := newTestClient("account-001")
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
		deleteFn: func() error { return nil },
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteClient_IDORProtection(t *testing.T) {
	client := newTestClient("other-account-999")
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
		deleteFn: func() error { return oauth2Service.ErrClientAccessDenied },
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/oauth2/clients/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}
