package service

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestSocialLoginService() *SocialLoginService {
	return &SocialLoginService{
		providers: map[string]*OAuthProviderConfig{
			"google": {
				ClientID:     "google-client-id",
				ClientSecret: "google-secret",
				RedirectURI:  "https://app.example.com/callback",
				Scopes:       []string{"openid", "email", "profile"},
				TokenURL:     "https://oauth2.googleapis.com/token",
				UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
			},
			"github": {
				ClientID:     "github-client-id",
				ClientSecret: "github-secret",
				RedirectURI:  "https://app.example.com/github/callback",
				Scopes:       []string{"user:email"},
				TokenURL:     "https://github.com/login/oauth/access_token",
				UserInfoURL:  "https://api.github.com/user",
			},
		},
		logger: zap.NewNop(),
	}
}

// ──────────────────────────────────────────────
// GetAuthURL
// ──────────────────────────────────────────────

func TestGetAuthURL_Google(t *testing.T) {
	svc := newTestSocialLoginService()
	authURL, err := svc.GetAuthURL(context.Background(), "google", "test-state-123")
	require.NoError(t, err)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	assert.Equal(t, "https", parsed.Scheme)
	assert.Equal(t, "accounts.google.com", parsed.Host)
	assert.Equal(t, "google-client-id", parsed.Query().Get("client_id"))
	assert.Equal(t, "test-state-123", parsed.Query().Get("state"))
	assert.Equal(t, "code", parsed.Query().Get("response_type"))
	assert.Equal(t, "https://app.example.com/callback", parsed.Query().Get("redirect_uri"))
}

func TestGetAuthURL_GitHub(t *testing.T) {
	svc := newTestSocialLoginService()
	authURL, err := svc.GetAuthURL(context.Background(), "github", "github-state")
	require.NoError(t, err)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	assert.Equal(t, "github.com", parsed.Host)
	assert.Equal(t, "github-client-id", parsed.Query().Get("client_id"))
	assert.Equal(t, "github-state", parsed.Query().Get("state"))
}

func TestGetAuthURL_UnsupportedProvider(t *testing.T) {
	svc := newTestSocialLoginService()
	_, err := svc.GetAuthURL(context.Background(), "facebook", "state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider")
}

func TestGetAuthURL_ScopesJoined(t *testing.T) {
	svc := newTestSocialLoginService()
	authURL, err := svc.GetAuthURL(context.Background(), "google", "state")
	require.NoError(t, err)

	parsed, _ := url.Parse(authURL)
	assert.Equal(t, "openid email profile", parsed.Query().Get("scope"))
}

// ──────────────────────────────────────────────
// NewSocialLoginService
// ──────────────────────────────────────────────

func TestNewSocialLoginService_NilLogger(t *testing.T) {
	svc := NewSocialLoginService(nil, nil, nil, nil, nil, nil, nil, map[string]*OAuthProviderConfig{}, nil)
	assert.NotNil(t, svc.logger)
}

func TestNewSocialLoginService_DefaultHTTPClient(t *testing.T) {
	svc := NewSocialLoginService(nil, nil, nil, nil, nil, nil, nil, map[string]*OAuthProviderConfig{}, nil)
	assert.NotNil(t, svc.httpClient)
	assert.Equal(t, 10*time.Second, svc.httpClient.Timeout)
}
