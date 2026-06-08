package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// Mock helpers for social login tests
// ──────────────────────────────────────────────

// mockSocialAccountService implements accountService.AccountService for social login tests.
type mockSocialAccountService struct {
	findByID func(ctx context.Context, accountID string) (*accountDomain.Account, error)
}

func (m *mockSocialAccountService) RegisterAccount(_ context.Context, _ *accountService.RegisterAccountRequest) (*accountDomain.Account, error) {
	panic("not implemented")
}
func (m *mockSocialAccountService) FindAccountByID(ctx context.Context, accountID string) (*accountDomain.Account, error) { //nolint:revive
	return m.findByID(ctx, accountID)
}
func (m *mockSocialAccountService) FindAccountByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	panic("not implemented")
}
func (m *mockSocialAccountService) UpdateAccount(_ context.Context, _ *accountDomain.Account) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) SoftDeleteAccount(_ context.Context, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) VerifyCredential(_ context.Context, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) ChangePassword(_ context.Context, _, _, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) BindFederatedIdentity(_ context.Context, _ string, _ accountDomain.Provider, _ string, _ map[string]interface{}) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) UnbindFederatedIdentity(_ context.Context, _, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) AssignRole(_ context.Context, _, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) RemoveRole(_ context.Context, _, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) ListAccounts(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	panic("not implemented")
}
func (m *mockSocialAccountService) SuspendAccount(_ context.Context, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) ActivateAccount(_ context.Context, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountService) GetAccountRoles(_ context.Context, _ string) ([]*accountDomain.Role, error) {
	panic("not implemented")
}

// mockSocialFederatedIdentityRepo implements accountRepo.FederatedIdentityRepository.
type mockSocialFederatedIdentityRepo struct {
	findByProvider func(ctx context.Context, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error)
}

func (m *mockSocialFederatedIdentityRepo) CreateFederatedIdentity(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
	panic("not implemented")
}
func (m *mockSocialFederatedIdentityRepo) FindByProvider(ctx context.Context, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error) { //nolint:revive
	return m.findByProvider(ctx, provider, providerUserID)
}
func (m *mockSocialFederatedIdentityRepo) FindByAccountID(_ context.Context, _ string) ([]*accountDomain.FederatedIdentity, error) {
	panic("not implemented")
}
func (m *mockSocialFederatedIdentityRepo) SoftDeleteByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	panic("not implemented")
}
func (m *mockSocialFederatedIdentityRepo) SoftDeleteByID(_ context.Context, _ *sql.Tx, _, _ string, _ time.Time) error {
	panic("not implemented")
}

// mockSocialSessionTokenCreator implements SessionTokenCreator.
type mockSocialSessionTokenCreator struct {
	create func(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error)
}

func (m *mockSocialSessionTokenCreator) CreateSessionAndTokens(ctx context.Context, account *accountDomain.Account, ip, userAgent string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
	return m.create(ctx, account, ip, userAgent)
}

// configurableMFAChecker is a test double that returns a configurable result.
type configurableMFAChecker struct {
	result *LoginResult
	err    error
}

func (c *configurableMFAChecker) CheckMFA(_ context.Context, _ *accountDomain.Account) (*LoginResult, error) {
	return c.result, c.err
}

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
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
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

// ──────────────────────────────────────────────
// exchangeCode
// ──────────────────────────────────────────────

func TestExchangeCode_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"test-token-123","token_type":"bearer"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := svc.providers["google"]
	p.TokenURL = ts.URL

	token, err := svc.exchangeCode(context.Background(), p, "auth-code-abc")
	require.NoError(t, err)
	assert.Equal(t, "test-token-123", token)
}

func TestExchangeCode_ErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := svc.providers["google"]
	p.TokenURL = ts.URL

	_, err := svc.exchangeCode(context.Background(), p, "bad-code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

func TestExchangeCode_MissingAccessToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token_type":"bearer"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := svc.providers["google"]
	p.TokenURL = ts.URL

	_, err := svc.exchangeCode(context.Background(), p, "code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no access_token")
}

func TestExchangeCode_MalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not json`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := svc.providers["google"]
	p.TokenURL = ts.URL

	_, err := svc.exchangeCode(context.Background(), p, "code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse token response")
}

func TestExchangeCode_ConnectionError(t *testing.T) {
	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURI:  "https://app.example.com/callback",
		TokenURL:     "http://127.0.0.1:1",
	}

	_, err := svc.exchangeCode(context.Background(), p, "code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token request")
}

// ──────────────────────────────────────────────
// fetchUserInfo
// ──────────────────────────────────────────────

func TestFetchUserInfo_Google_Float64ID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":123456789,"email":"user@gmail.com","name":"Test User","email_verified":true}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	id, email, name, verified, err := svc.fetchUserInfo(context.Background(), "google", p, "tok")
	require.NoError(t, err)
	assert.Equal(t, "123456789", id)
	assert.Equal(t, "user@gmail.com", email)
	assert.Equal(t, "Test User", name)
	assert.True(t, verified)
}

func TestFetchUserInfo_GitHub_StringID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"gh-42","email":"dev@github.com","name":"GH Dev"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	id, email, name, _, err := svc.fetchUserInfo(context.Background(), "github", p, "tok")
	require.NoError(t, err)
	assert.Equal(t, "gh-42", id)
	assert.Equal(t, "dev@github.com", email)
	assert.Equal(t, "GH Dev", name)
}

func TestFetchUserInfo_WeChat_OpenID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openid":"wx-openid-123","nickname":"微信用户"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	id, email, name, verified, err := svc.fetchUserInfo(context.Background(), "wechat", p, "tok")
	require.NoError(t, err)
	assert.Equal(t, "wx-openid-123", id)
	assert.Equal(t, "", email)
	assert.Equal(t, "微信用户", name)
	assert.False(t, verified)
}

func TestFetchUserInfo_WeChat_MissingOpenID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"nickname":"User"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	_, _, _, _, err := svc.fetchUserInfo(context.Background(), "wechat", p, "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing or empty openid")
}

func TestFetchUserInfo_MissingID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"email":"user@example.com","name":"User"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	_, _, _, _, err := svc.fetchUserInfo(context.Background(), "google", p, "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing or invalid id")
}

func TestFetchUserInfo_ErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	_, _, _, _, err := svc.fetchUserInfo(context.Background(), "google", p, "bad-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestFetchUserInfo_UnsupportedProvider(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"1","name":"User"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	_, _, _, _, err := svc.fetchUserInfo(context.Background(), "twitter", p, "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedProvider)
}

// ──────────────────────────────────────────────
// HandleCallback — error paths
// ──────────────────────────────────────────────

func TestHandleCallback_UnsupportedProvider(t *testing.T) {
	svc := newTestSocialLoginService()
	_, err := svc.HandleCallback(context.Background(), "twitter", "code", "127.0.0.1", "test-agent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedProvider)
}

func TestHandleCallback_ExchangeFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_code"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	svc.providers["google"].TokenURL = ts.URL

	_, err := svc.HandleCallback(context.Background(), "google", "bad-code", "127.0.0.1", "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exchange code")
}

func TestHandleCallback_FetchUserFailure(t *testing.T) {
	tokenTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok-123"}`)
	}))
	defer tokenTS.Close()

	userInfoTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer userInfoTS.Close()

	svc := newTestSocialLoginService()
	svc.providers["google"].TokenURL = tokenTS.URL
	svc.providers["google"].UserInfoURL = userInfoTS.URL

	_, err := svc.HandleCallback(context.Background(), "google", "code", "127.0.0.1", "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch user info")
}

// ──────────────────────────────────────────────
// loginExistingUser
// ──────────────────────────────────────────────

func TestLoginExistingUser_Success(t *testing.T) {
	account := &accountDomain.Account{
		ID:          "acc-123",
		DisplayName: "Social User",
		Status:      accountDomain.AccountStatusActive,
	}
	svc := newTestSocialLoginService()
	svc.accountSvc = &mockSocialAccountService{
		findByID: func(_ context.Context, id string) (*accountDomain.Account, error) {
			assert.Equal(t, "acc-123", id)
			return account, nil
		},
	}
	svc.sessionTokenCreator = &mockSocialSessionTokenCreator{
		create: func(_ context.Context, acc *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
			assert.Equal(t, account, acc)
			return &sessionDomain.Session{ID: "sess-1"}, "access-tok", &tokenDomain.RefreshToken{Token: "refresh-tok"}, nil
		},
	}

	result, err := svc.loginExistingUser(context.Background(), "acc-123", "127.0.0.1", "agent")
	require.NoError(t, err)
	assert.Equal(t, account, result.Account)
	assert.Equal(t, "access-tok", result.AccessToken)
	assert.Equal(t, "refresh-tok", result.RefreshToken)
	assert.Equal(t, "sess-1", result.Session.ID)
}

func TestLoginExistingUser_MFARequired(t *testing.T) {
	account := &accountDomain.Account{
		ID:          "acc-mfa",
		DisplayName: "MFA User",
		Status:      accountDomain.AccountStatusActive,
	}
	mfaResult := &LoginResult{
		Account:     account,
		RequiresMFA: true,
		MFATypes:    []string{"totp"},
	}
	svc := newTestSocialLoginService()
	svc.accountSvc = &mockSocialAccountService{
		findByID: func(_ context.Context, _ string) (*accountDomain.Account, error) {
			return account, nil
		},
	}
	svc.mfaChecker = &configurableMFAChecker{result: mfaResult}

	result, err := svc.loginExistingUser(context.Background(), "acc-mfa", "127.0.0.1", "agent")
	require.NoError(t, err)
	assert.True(t, result.RequiresMFA)
	assert.Equal(t, []string{"totp"}, result.MFATypes)
}

func TestLoginExistingUser_AccountNotFound(t *testing.T) {
	svc := newTestSocialLoginService()
	svc.accountSvc = &mockSocialAccountService{
		findByID: func(_ context.Context, _ string) (*accountDomain.Account, error) {
			return nil, errors.New("no rows")
		},
	}

	_, err := svc.loginExistingUser(context.Background(), "missing-acc", "127.0.0.1", "agent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountNotFound)
}

func TestLoginExistingUser_AccountNotActive(t *testing.T) {
	account := &accountDomain.Account{
		ID:          "acc-suspended",
		DisplayName: "Suspended",
		Status:      accountDomain.AccountStatusSuspended,
	}
	svc := newTestSocialLoginService()
	svc.accountSvc = &mockSocialAccountService{
		findByID: func(_ context.Context, _ string) (*accountDomain.Account, error) {
			return account, nil
		},
	}

	_, err := svc.loginExistingUser(context.Background(), "acc-suspended", "127.0.0.1", "agent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAccountNotActive)
}
