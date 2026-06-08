package service

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
)

func newTestSocialLoginService() *SocialLoginService {
	return &SocialLoginService{
		providers: map[string]*OAuthProviderConfig{
			"google": {
				ClientID:     "google-client-id",
				ClientSecret: "google-secret",
				RedirectURI:  "https://app.example.com/callback",
				Scopes:       []string{"openid", "email", "profile"},
				AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL:     "https://oauth2.googleapis.com/token",
				UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
			},
			"github": {
				ClientID:     "github-client-id",
				ClientSecret: "github-secret",
				RedirectURI:  "https://app.example.com/github/callback",
				Scopes:       []string{"user:email"},
				AuthURL:      "https://github.com/login/oauth/authorize",
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
	svc := NewSocialLoginService(nil, nil, nil, nil, nil, nil, map[string]*OAuthProviderConfig{}, nil)
	assert.NotNil(t, svc.logger)
}

func TestNewSocialLoginService_DefaultHTTPClient(t *testing.T) {
	svc := NewSocialLoginService(nil, nil, nil, nil, nil, nil, map[string]*OAuthProviderConfig{}, nil)
	assert.NotNil(t, svc.httpClient)
	assert.Equal(t, 10*time.Second, svc.httpClient.Timeout)
}

// ──────────────────────────────────────────────
// GenerateAuthState
// ──────────────────────────────────────────────

func TestGenerateAuthState(t *testing.T) {
	state, err := GenerateAuthState()
	require.NoError(t, err)
	assert.Len(t, state, 64) // 32 bytes = 64 hex chars
}

func TestGenerateAuthState_Unique(t *testing.T) {
	s1, err := GenerateAuthState()
	require.NoError(t, err)
	s2, err := GenerateAuthState()
	require.NoError(t, err)
	assert.NotEqual(t, s1, s2)
}

// ──────────────────────────────────────────────
// SetAuditor
// ──────────────────────────────────────────────

func TestSocialLoginService_SetAuditor(t *testing.T) {
	svc := newTestSocialLoginService()
	assert.Nil(t, svc.auditor)
	// SetAuditor accepts nil (no-op for audit-disabled mode)
	svc.SetAuditor(nil)
	assert.Nil(t, svc.auditor)
}

// ──────────────────────────────────────────────
// SetMFAChecker
// ──────────────────────────────────────────────

func TestSetMFAChecker_SetsChecker(t *testing.T) {
	svc := newTestSocialLoginService()
	checker := &testMFAChecker{}
	svc.SetMFAChecker(checker)
	assert.Equal(t, checker, svc.mfaChecker)
}

func TestSetMFAChecker_NilPanics(t *testing.T) {
	svc := newTestSocialLoginService()
	assert.Panics(t, func() { svc.SetMFAChecker(nil) })
}

type testMFAChecker struct{}

func (t *testMFAChecker) CheckMFA(_ context.Context, _ *accountDomain.Account) (*LoginResult, error) {
	return nil, nil
}

// ──────────────────────────────────────────────
// isUniqueViolation
// ──────────────────────────────────────────────

func TestIsUniqueViolation_Nil(t *testing.T) {
	assert.False(t, isUniqueViolation(nil))
}

func TestIsUniqueViolation_PgError(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505"}
	assert.True(t, isUniqueViolation(pgErr))
}

func TestIsUniqueViolation_PgErrorOtherCode(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23503"}
	assert.False(t, isUniqueViolation(pgErr))
}

func TestIsUniqueViolation_SQLiteError(t *testing.T) {
	err := errors.New("UNIQUE constraint failed: users.email")
	assert.True(t, isUniqueViolation(err))
}

func TestIsUniqueViolation_RegularError(t *testing.T) {
	err := errors.New("something else")
	assert.False(t, isUniqueViolation(err))
}
