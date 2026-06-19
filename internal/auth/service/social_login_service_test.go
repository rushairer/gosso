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

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	accountService "github.com/rushairer/gosso/internal/account/service"
	sessionDomain "github.com/rushairer/gosso/internal/session/domain"
	"github.com/rushairer/gosso/internal/testutil"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

// ──────────────────────────────────────────────
// Mock helpers for social login tests
// ──────────────────────────────────────────────

func newHTTPTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	testutil.RequireLocalHTTPServer(t)
	return httptest.NewServer(handler)
}

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
func (m *mockSocialAccountService) VerifyContactCredential(_ context.Context, _ string) error {
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
func (m *mockSocialAccountService) SetOptions(_ *accountService.AccountServiceOptions) {}

// mockSocialFederatedIdentityRepo implements accountRepo.FederatedIdentityRepository.
type mockSocialFederatedIdentityRepo struct {
	findByProvider          func(ctx context.Context, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error)
	createFederatedIdentity func(ctx context.Context, tx *sql.Tx, identity *accountDomain.FederatedIdentity) error
}

func (m *mockSocialFederatedIdentityRepo) CreateFederatedIdentity(ctx context.Context, tx *sql.Tx, identity *accountDomain.FederatedIdentity) error {
	if m.createFederatedIdentity != nil {
		return m.createFederatedIdentity(ctx, tx, identity)
	}
	panic("CreateFederatedIdentity not configured")
}
func (m *mockSocialFederatedIdentityRepo) FindByProvider(ctx context.Context, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error) { //nolint:revive
	return m.findByProvider(ctx, provider, providerUserID)
}
func (m *mockSocialFederatedIdentityRepo) FindByAccountID(_ context.Context, _ string) ([]*accountDomain.FederatedIdentity, error) {
	panic("not implemented")
}
func (m *mockSocialFederatedIdentityRepo) FindByAccountIDTx(_ context.Context, _ *sql.Tx, _ string) ([]*accountDomain.FederatedIdentity, error) {
	panic("not implemented")
}
func (m *mockSocialFederatedIdentityRepo) SoftDeleteByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	panic("not implemented")
}
func (m *mockSocialFederatedIdentityRepo) SoftDeleteByID(_ context.Context, _ *sql.Tx, _, _ string, _ time.Time) error {
	panic("not implemented")
}
func (m *mockSocialFederatedIdentityRepo) FindByProviderTx(ctx context.Context, _ *sql.Tx, provider accountDomain.Provider, providerUserID string) (*accountDomain.FederatedIdentity, error) {
	return m.findByProvider(ctx, provider, providerUserID)
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
		federatedIdentityRepo: &mockSocialFederatedIdentityRepo{
			findByProvider: func(_ context.Context, _ accountDomain.Provider, _ string) (*accountDomain.FederatedIdentity, error) {
				return nil, accountRepo.ErrFederatedIdentityNotFound
			},
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
	svc, err := NewSocialLoginService(nil, nil, nil, nil, nil, nil, map[string]*OAuthProviderConfig{}, nil, nil, nil, 0)
	assert.NoError(t, err)
	assert.NotNil(t, svc.logger)
}

func TestNewSocialLoginService_DefaultHTTPClient(t *testing.T) {
	svc, err := NewSocialLoginService(nil, nil, nil, nil, nil, nil, map[string]*OAuthProviderConfig{}, nil, nil, nil, 0)
	assert.NoError(t, err)
	assert.NotNil(t, svc.httpClient)
	assert.Equal(t, 10*time.Second, svc.httpClient.Timeout)
}

func TestNewSocialLoginService_RejectsHTTProvider(t *testing.T) {
	providers := map[string]*OAuthProviderConfig{
		"google": {
			ClientID: "id",
			AuthURL:  "http://accounts.google.com/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}
	_, err := NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, nil, nil, nil, 0)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderURLNotSecure)
}

func TestNewSocialLoginService_AllowsLocalhost(t *testing.T) {
	providers := map[string]*OAuthProviderConfig{
		"dev": {
			ClientID: "id",
			AuthURL:  "http://localhost:8080/auth",
			TokenURL: "http://127.0.0.1:8080/token",
		},
	}
	svc, err := NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, nil, nil, nil, 0)
	assert.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestNewSocialLoginService_AllowsHTTPS(t *testing.T) {
	providers := map[string]*OAuthProviderConfig{
		"google": {
			ClientID: "id",
			AuthURL:  "https://accounts.google.com/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}
	svc, err := NewSocialLoginService(nil, nil, nil, nil, nil, nil, providers, nil, nil, nil, 0)
	assert.NoError(t, err)
	assert.NotNil(t, svc)
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
// Mock helpers for createNewUser tests
// ──────────────────────────────────────────────

// mockSocialAccountRepo implements accountRepo.AccountRepository.
type mockSocialAccountRepo struct {
	createAccount func(ctx context.Context, tx *sql.Tx, account *accountDomain.Account) error
}

func (m *mockSocialAccountRepo) CreateAccount(ctx context.Context, tx *sql.Tx, account *accountDomain.Account) error {
	return m.createAccount(ctx, tx, account)
}
func (m *mockSocialAccountRepo) FindByID(_ context.Context, _ string) (*accountDomain.Account, error) {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) FindByIDTx(_ context.Context, _ *sql.Tx, _ string) (*accountDomain.Account, error) {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) FindByIDIncludingDeletedTx(_ context.Context, _ *sql.Tx, _ string) (*accountDomain.Account, error) {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) FindByUsername(_ context.Context, _ string) (*accountDomain.Account, error) {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) UpdateAccount(_ context.Context, _ *sql.Tx, _ *accountDomain.Account, _ time.Time) error {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) SoftDeleteAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) FindAll(_ context.Context, _, _ int, _ string) ([]*accountDomain.Account, int, error) {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) SuspendAccount(_ context.Context, _ *sql.Tx, _ string) error {
	panic("not implemented")
}
func (m *mockSocialAccountRepo) ActivateAccount(_ context.Context, _ *sql.Tx, _ string) error {
	panic("not implemented")
}

// mockSocialCredentialRepo implements accountRepo.CredentialRepository.
type mockSocialCredentialRepo struct {
	findByTypeAndIdentifier func(ctx context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error)
	createCredentials       func(ctx context.Context, tx *sql.Tx, credentials []*accountDomain.Credential) error
}

func (m *mockSocialCredentialRepo) CreateCredentials(ctx context.Context, tx *sql.Tx, credentials []*accountDomain.Credential) error {
	return m.createCredentials(ctx, tx, credentials)
}
func (m *mockSocialCredentialRepo) FindByAccountAndType(_ context.Context, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) FindByTypeAndIdentifier(ctx context.Context, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	return m.findByTypeAndIdentifier(ctx, credType, identifier)
}
func (m *mockSocialCredentialRepo) FindPasswordCredential(_ context.Context, _ string) (*accountDomain.Credential, error) {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) UpdateCredential(_ context.Context, _ *sql.Tx, _ *accountDomain.Credential) error {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) UpdateLastUsedAt(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockSocialCredentialRepo) SoftDeleteCredentialsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) FindByAccountAndTypeForUpdate(_ context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) VerifyFirstUnverifiedTOTP(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) FindByAccountAndTypeTx(ctx context.Context, _ *sql.Tx, _ string, _ accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	panic("not implemented")
}
func (m *mockSocialCredentialRepo) FindByTypeAndIdentifierTx(ctx context.Context, _ *sql.Tx, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	return m.findByTypeAndIdentifier(ctx, credType, identifier)
}

// createNewUserTestHarness bundles the service and mocks for createNewUser tests.
type createNewUserTestHarness struct {
	svc             *SocialLoginService
	sqlMock         sqlmock.Sqlmock
	accountRepo     *mockSocialAccountRepo
	credentialRepo  *mockSocialCredentialRepo
	fedIdentityRepo *mockSocialFederatedIdentityRepo
	sessionCreator  *mockSocialSessionTokenCreator
	accountSvc      *mockSocialAccountService
}

func setupCreateNewUserService(t *testing.T) *createNewUserTestHarness {
	t.Helper()

	db, sm, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ar := &mockSocialAccountRepo{}
	cr := &mockSocialCredentialRepo{}
	fi := &mockSocialFederatedIdentityRepo{}
	sc := &mockSocialSessionTokenCreator{}
	as := &mockSocialAccountService{}

	svc := &SocialLoginService{
		db:                    db,
		accountSvc:            as,
		sessionTokenCreator:   sc,
		accountRepo:           ar,
		credentialRepo:        cr,
		federatedIdentityRepo: fi,
		providers:             map[string]*OAuthProviderConfig{},
		httpClient:            &http.Client{Timeout: 10 * time.Second},
		logger:                zap.NewNop(),
	}

	return &createNewUserTestHarness{
		svc:             svc,
		sqlMock:         sm,
		accountRepo:     ar,
		credentialRepo:  cr,
		fedIdentityRepo: fi,
		sessionCreator:  sc,
		accountSvc:      as,
	}
}

// common test fixtures for loginExistingUser paths
var (
	fixtureExistingAccount = &accountDomain.Account{
		ID:          "existing-acc-456",
		DisplayName: "Existing User",
		Status:      accountDomain.AccountStatusActive,
	}
)

// ──────────────────────────────────────────────
// exchangeCode
// ──────────────────────────────────────────────

func TestExchangeCode_Success(t *testing.T) {
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"1","name":"User"}`)
	}))
	defer ts.Close()

	svc := newTestSocialLoginService()
	p := &OAuthProviderConfig{UserInfoURL: ts.URL}

	_, _, _, _, err := svc.fetchUserInfo(context.Background(), "twitter", p, "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, accountDomain.ErrUnsupportedProvider)
}

// ──────────────────────────────────────────────
// HandleCallback — error paths
// ──────────────────────────────────────────────

func TestHandleCallback_UnsupportedProvider(t *testing.T) {
	svc := newTestSocialLoginService()
	_, err := svc.HandleCallback(context.Background(), "twitter", "code", "127.0.0.1", "test-agent")
	require.Error(t, err)
	assert.ErrorIs(t, err, accountDomain.ErrUnsupportedProvider)
}

func TestHandleCallback_ExchangeFailure(t *testing.T) {
	ts := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	tokenTS := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok-123"}`)
	}))
	defer tokenTS.Close()

	userInfoTS := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	assert.Contains(t, err.Error(), "find account for social login")
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
	assert.ErrorIs(t, err, accountService.ErrAccountNotActive)
}
func TestCreateNewUser_NewAccountSuccess(t *testing.T) {
	h := setupCreateNewUserService(t)

	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return nil, accountRepo.ErrCredentialNotFound
	}
	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return nil
	}
	h.credentialRepo.createCredentials = func(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
		return nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-1"}, "access-token-1", &tokenDomain.RefreshToken{Token: "refresh-1"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-123", "user@example.com", "Test User", true, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.Account)
	assert.Equal(t, "Test User", result.Account.DisplayName)
	assert.Equal(t, "sess-1", result.Session.ID)
	assert.Equal(t, "access-token-1", result.AccessToken)
	assert.Equal(t, "refresh-1", result.RefreshToken)
}

func TestCreateNewUser_NewAccountNoEmail(t *testing.T) {
	h := setupCreateNewUserService(t)

	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-2"}, "access-token-2", &tokenDomain.RefreshToken{Token: "refresh-2"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-456", "", "", false, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.Account)
	assert.Equal(t, "User", result.Account.DisplayName)
	assert.Equal(t, "sess-2", result.Session.ID)
}

func TestCreateNewUser_NewAccountEmailVerified(t *testing.T) {
	h := setupCreateNewUserService(t)

	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return nil, accountRepo.ErrCredentialNotFound
	}
	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return nil
	}
	var capturedCreds []*accountDomain.Credential
	h.credentialRepo.createCredentials = func(_ context.Context, _ *sql.Tx, creds []*accountDomain.Credential) error {
		capturedCreds = creds
		return nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-3"}, "access-token-3", &tokenDomain.RefreshToken{Token: "refresh-3"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-789", "new@example.com", "New User", true, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, capturedCreds, 1)
	assert.True(t, capturedCreds[0].Verified)
	assert.True(t, capturedCreds[0].PrimaryCredential)
	assert.Equal(t, accountDomain.CredentialTypeEmail, capturedCreds[0].Type)
}

func TestCreateNewUser_ExistingVerifiedEmail_LinkSuccess(t *testing.T) {
	h := setupCreateNewUserService(t)

	email := "existing@example.com"
	verifiedCred := &accountDomain.Credential{
		ID:         "cred-123",
		AccountID:  "existing-acc-456",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   true,
	}
	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return verifiedCred, nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.accountSvc.findByID = func(_ context.Context, _ string) (*accountDomain.Account, error) {
		return fixtureExistingAccount, nil
	}
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-4"}, "access-token-4", &tokenDomain.RefreshToken{Token: "refresh-4"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-link", "existing@example.com", "Existing", false, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "existing-acc-456", result.Account.ID)
	assert.Equal(t, "sess-4", result.Session.ID)
}

func TestCreateNewUser_ExistingVerifiedEmail_LinkUniqueViolation(t *testing.T) {
	h := setupCreateNewUserService(t)

	email := "existing@example.com"
	verifiedCred := &accountDomain.Credential{
		ID:         "cred-123",
		AccountID:  "existing-acc-456",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   true,
	}
	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return verifiedCred, nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return &pgconn.PgError{Code: "23505"}
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()
	h.accountSvc.findByID = func(_ context.Context, _ string) (*accountDomain.Account, error) {
		return fixtureExistingAccount, nil
	}
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-5"}, "access-token-5", &tokenDomain.RefreshToken{Token: "refresh-5"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-link-uv", "existing@example.com", "Existing", false, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "existing-acc-456", result.Account.ID)
}

func TestCreateNewUser_ExistingVerifiedEmail_LinkError(t *testing.T) {
	h := setupCreateNewUserService(t)

	email := "existing@example.com"
	verifiedCred := &accountDomain.Credential{
		ID:         "cred-123",
		AccountID:  "existing-acc-456",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   true,
	}
	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return verifiedCred, nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return errors.New("database connection lost")
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-link-err", "existing@example.com", "Existing", false, "127.0.0.1", "test-agent")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "link federated identity")
}

func TestCreateNewUser_UnverifiedEmail_CreatesNewAccount(t *testing.T) {
	h := setupCreateNewUserService(t)

	email := "unverified@example.com"
	unverifiedCred := &accountDomain.Credential{
		ID:         "cred-unverified",
		AccountID:  "other-acc",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   false,
	}
	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return unverifiedCred, nil
	}
	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return nil
	}
	h.credentialRepo.createCredentials = func(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
		return nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-7"}, "access-token-7", &tokenDomain.RefreshToken{Token: "refresh-7"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "github", "gh-uid", "unverified@example.com", "Unverified", false, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.Account)
	assert.Equal(t, "Unverified", result.Account.DisplayName)
}

func TestCreateNewUser_RaceCondition_RetryLinkSuccess(t *testing.T) {
	h := setupCreateNewUserService(t)

	email := "race@example.com"
	verifiedCred := &accountDomain.Credential{
		ID:         "cred-race",
		AccountID:  "existing-acc-456",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   true,
	}
	findCall := 0
	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		findCall++
		if findCall == 1 {
			return nil, accountRepo.ErrCredentialNotFound
		}
		return verifiedCred, nil
	}
	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return &pgconn.PgError{Code: "23505"}
	}
	// First transaction: Begin → CreateAccount fails → Rollback
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()
	// Second transaction (link): Begin → CreateFederatedIdentity succeeds → Commit
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.accountSvc.findByID = func(_ context.Context, _ string) (*accountDomain.Account, error) {
		return fixtureExistingAccount, nil
	}
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-8"}, "access-token-8", &tokenDomain.RefreshToken{Token: "refresh-8"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-race", "race@example.com", "Racer", false, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "existing-acc-456", result.Account.ID)
}

func TestCreateNewUser_RaceCondition_RetryLinkUniqueViolation(t *testing.T) {
	h := setupCreateNewUserService(t)

	email := "race2@example.com"
	verifiedCred := &accountDomain.Credential{
		ID:         "cred-race2",
		AccountID:  "existing-acc-456",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   true,
	}
	findCall := 0
	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		findCall++
		if findCall == 1 {
			return nil, accountRepo.ErrCredentialNotFound
		}
		return verifiedCred, nil
	}
	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return &pgconn.PgError{Code: "23505"}
	}
	// First transaction: Begin → CreateAccount fails → Rollback
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()
	// Second transaction (link): Begin → CreateFederatedIdentity unique violation → Rollback
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return &pgconn.PgError{Code: "23505"}
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()
	h.accountSvc.findByID = func(_ context.Context, _ string) (*accountDomain.Account, error) {
		return fixtureExistingAccount, nil
	}
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return &sessionDomain.Session{ID: "sess-9"}, "access-token-9", &tokenDomain.RefreshToken{Token: "refresh-9"}, nil
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-race2", "race2@example.com", "Racer2", false, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "existing-acc-456", result.Account.ID)
}

func TestCreateNewUser_RaceCondition_RetryFindFails(t *testing.T) {
	h := setupCreateNewUserService(t)

	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		return nil, accountRepo.ErrCredentialNotFound
	}
	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return &pgconn.PgError{Code: "23505"}
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-race3", "race3@example.com", "Racer3", false, "127.0.0.1", "test-agent")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "create account")
}

func TestCreateNewUser_RaceCondition_RetryLinkError(t *testing.T) {
	h := setupCreateNewUserService(t)

	email := "race4@example.com"
	verifiedCred := &accountDomain.Credential{
		ID:         "cred-race4",
		AccountID:  "existing-acc-456",
		Type:       accountDomain.CredentialTypeEmail,
		Identifier: &email,
		Verified:   true,
	}
	findCall := 0
	h.credentialRepo.findByTypeAndIdentifier = func(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
		findCall++
		if findCall == 1 {
			return nil, accountRepo.ErrCredentialNotFound
		}
		return verifiedCred, nil
	}
	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return &pgconn.PgError{Code: "23505"}
	}
	// First transaction: Begin → CreateAccount fails → Rollback
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()
	// Second transaction (link): Begin → CreateFederatedIdentity non-unique error → Rollback
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return errors.New("connection timeout")
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-race4", "race4@example.com", "Racer4", false, "127.0.0.1", "test-agent")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "link federated identity")
}

func TestCreateNewUser_CreateAccount_NonUniqueError(t *testing.T) {
	h := setupCreateNewUserService(t)

	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return errors.New("connection refused")
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectRollback()

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-err", "", "Error User", false, "127.0.0.1", "test-agent")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "create account")
}

func TestCreateNewUser_MFARequired(t *testing.T) {
	h := setupCreateNewUserService(t)

	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.svc.mfaChecker = &configurableMFAChecker{
		result: &LoginResult{RequiresMFA: true, MFATypes: []string{"totp"}},
	}
	// Don't set sessionCreator.create — if called, nil func panics = implicit assertion

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-mfa", "", "MFA User", false, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.RequiresMFA)
	assert.Equal(t, []string{"totp"}, result.MFATypes)
}

func TestCreateNewUser_SessionTokenCreationFails(t *testing.T) {
	h := setupCreateNewUserService(t)

	h.accountRepo.createAccount = func(_ context.Context, _ *sql.Tx, _ *accountDomain.Account) error {
		return nil
	}
	h.fedIdentityRepo.createFederatedIdentity = func(_ context.Context, _ *sql.Tx, _ *accountDomain.FederatedIdentity) error {
		return nil
	}
	h.sqlMock.ExpectBegin()
	h.sqlMock.ExpectCommit()
	h.sessionCreator.create = func(_ context.Context, _ *accountDomain.Account, _, _ string) (*sessionDomain.Session, string, *tokenDomain.RefreshToken, error) {
		return nil, "", nil, errors.New("redis connection failed")
	}

	result, err := h.svc.createNewUser(context.Background(), "google", "google-uid-sess-fail", "", "Fail User", false, "127.0.0.1", "test-agent")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "redis connection failed")
}
