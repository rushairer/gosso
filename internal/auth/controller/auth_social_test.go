package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/auth/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// SocialAuthURL tests
// ──────────────────────────────────────────────

func TestSocialAuthURL_NilService(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
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
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil, 0)
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
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil, 0)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/facebook", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ──────────────────────────────────────────────
// SocialCallback tests
// ──────────────────────────────────────────────

func TestSocialCallback_NilService(t *testing.T) {
	authSvc := &mockAuthOrchestrator{}
	tokenMgr := &mockTokenManager{}
	engine, _ := setupAuthController(authSvc, tokenMgr)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestSocialCallback_MissingState(t *testing.T) {
	providers := map[string]*service.OAuthProviderConfig{
		"google": {AuthURL: "https://accounts.google.com/o/oauth2/v2/auth"},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil, 0)
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
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil, 0)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=state-a:192.0.2.1&code=test-code", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "state-b"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSocialCallback_MissingCode(t *testing.T) {
	providers := map[string]*service.OAuthProviderConfig{
		"google": {AuthURL: "https://accounts.google.com/o/oauth2/v2/auth"},
	}
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil, 0)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=test-state:192.0.2.1", nil)
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
	socialSvc, _ := service.NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, zap.NewNop(), nil, nil, 0)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=test-state:192.0.2.1&code=bad-code", nil)
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
	socialSvc, _ := service.NewSocialLoginService(nil, accountSvc, sessionCreator, nil, nil, fedIdentityRepo, providers, zap.NewNop(), nil, nil, 0)
	engine := setupAuthControllerWithSocial(socialSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/social/google/callback?state=test-state:192.0.2.1&code=good-code", nil)
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
