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

	"github.com/rushairer/gosso/internal/auth/middleware"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// Mock OAuth2ClientService
// ──────────────────────────────────────────────

type mockOAuth2ClientService struct {
	registerFn    func() (*oauth2Domain.OAuth2Client, string, error)
	findByIDFn    func() (*oauth2Domain.OAuth2Client, error)
	findByAcctFn  func() ([]*oauth2Domain.OAuth2Client, error)
	updateFn      func() error
	deleteFn      func() error
}

func (m *mockOAuth2ClientService) RegisterClient(_ context.Context, _ *oauth2Service.RegisterClientRequest) (*oauth2Domain.OAuth2Client, string, error) {
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

func (m *mockOAuth2ClientService) DeleteClient(_ context.Context, _ string) error {
	if m.deleteFn != nil {
		return m.deleteFn()
	}
	return nil
}

// ──────────────────────────────────────────────
// Mock TokenManager (local interface)
// ──────────────────────────────────────────────

type mockOAuth2TokenManager struct{}

func (m *mockOAuth2TokenManager) GenerateAccessToken(_ *tokenDomain.AccessTokenClaims) (string, error) {
	return "mock-token", nil
}

func (m *mockOAuth2TokenManager) GenerateRefreshToken(_ context.Context, _, _, _, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "mock-refresh"}, nil
}

func (m *mockOAuth2TokenManager) RotateRefreshToken(_ context.Context, _ string) (*tokenDomain.RefreshToken, error) {
	return &tokenDomain.RefreshToken{Token: "rotated"}, nil
}

func (m *mockOAuth2TokenManager) RevokeRefreshToken(_ context.Context, _ string) error { return nil }

func (m *mockOAuth2TokenManager) IntrospectToken(_ context.Context, _ string) (map[string]any, error) {
	return map[string]any{"active": true}, nil
}

func (m *mockOAuth2TokenManager) AccessExpiry() time.Duration { return 15 * time.Minute }

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

func newTestClient(accountID string) *oauth2Domain.OAuth2Client {
	return &oauth2Domain.OAuth2Client{
		ID:             "client-uuid-001",
		AccountID:      accountID,
		ClientID:       "cid-abc123",
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
	assert.Equal(t, "cid-abc123", data["client_id"])
	assert.Equal(t, "secret-123", data["client_secret"])
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

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients/cid-abc123", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients/nonexistent", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
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

	req := httptest.NewRequest(http.MethodGet, "/api/oauth2/clients/cid-abc123", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateClient_Success(t *testing.T) {
	client := newTestClient("account-001")
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
		updateFn: func() error { return nil },
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Updated App","description":"Updated description"}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/cid-abc123", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateClient_IDORProtection(t *testing.T) {
	client := newTestClient("other-account-999")
	clientSvc := &mockOAuth2ClientService{
		findByIDFn: func() (*oauth2Domain.OAuth2Client, error) {
			return client, nil
		},
	}
	engine := setupClientController(clientSvc)

	body := `{"name":"Hacked Name"}`
	req := httptest.NewRequest(http.MethodPut, "/api/oauth2/clients/cid-abc123", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
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

	req := httptest.NewRequest(http.MethodDelete, "/api/oauth2/clients/cid-abc123", nil)
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
	}
	engine := setupClientController(clientSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/oauth2/clients/cid-abc123", nil)
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}
