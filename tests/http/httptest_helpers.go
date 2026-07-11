//go:build integration

package http_test

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/account"
	accountService "github.com/rushairer/gosso/internal/account/service"
	adminController "github.com/rushairer/gosso/internal/admin/controller"
	auditRepository "github.com/rushairer/gosso/internal/audit/repository"
	"github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/auth"
	authController "github.com/rushairer/gosso/internal/auth/controller"
	authServicePkg "github.com/rushairer/gosso/internal/auth/service"
	"github.com/rushairer/gosso/internal/oauth2"
	oauth2Controller "github.com/rushairer/gosso/internal/oauth2/controller"
	oauth2Domain "github.com/rushairer/gosso/internal/oauth2/domain"
	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	oauth2Service "github.com/rushairer/gosso/internal/oauth2/service"
	"github.com/rushairer/gosso/internal/oidc"
	oidcController "github.com/rushairer/gosso/internal/oidc/controller"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	"github.com/rushairer/gosso/internal/testutil"
	tokenServicePkg "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/middleware"
	"github.com/rushairer/gosso/router"
)

// HTTPTestEnv wraps testutil.TestEnv with a fully wired Gin HTTP test server.
type HTTPTestEnv struct {
	*testutil.TestEnv
	Server        *httptest.Server
	Client        *http.Client
	Engine        *gin.Engine
	TokenSvc      *tokenServicePkg.TokenService
	KeySvc        *tokenServicePkg.KeyService
	SessionSvc    *sessionService.SessionService
	OAuth2Ctrl    *oauth2Controller.OAuth2Controller
	OIDCCtrl      *oidcController.OIDCController
	AccountModule *account.AccountModule
	AuthModule    *auth.AuthModule
	OAuth2Module  *oauth2.OAuth2Module
	Issuer        string
}

// SeedClientOptions configures the OAuth2 client to seed.
type SeedClientOptions struct {
	Name                              string
	Confidential                      bool
	RedirectURIs                      []string
	PostLogoutRedirectURIs            []string
	GrantTypes                        []string
	Scopes                            []string
	FrontchannelLogoutURI             string
	FrontchannelLogoutSessionRequired bool
	BackchannelLogoutURI              string
	BackchannelLogoutSessionRequired  bool
}

// SetupHTTPTestEnv creates a full Gin HTTP test server with real DB + Redis.
func SetupHTTPTestEnv(t *testing.T) *HTTPTestEnv {
	t.Helper()

	gin.SetMode(gin.TestMode)

	env := testutil.SetupTestEnvT(t)
	ctx := context.Background()
	require.NoError(t, env.TruncateAll(ctx))
	logger := zap.NewNop()

	auditor := service.NewAuditor(ctx, env.DB, nil, logger)
	accountMod := account.InitializeAccountModule(env.DB, auditor, logger, nil)

	keySvc, err := tokenServicePkg.NewKeyService("", "test-key", false, 0, logger)
	require.NoError(t, err)

	blacklistSvc, err := tokenServicePkg.NewBlacklistService(env.Redis, logger)
	require.NoError(t, err)

	tokenSvc, err := tokenServicePkg.NewTokenService(
		keySvc,
		"http://localhost",
		env.Config.AuthConfig.AccessTokenExpiry,
		env.Config.AuthConfig.RefreshTokenExpiry,
		env.Redis,
		blacklistSvc,
		nil,
		false,
		logger,
	)
	require.NoError(t, err)

	authMod, err := auth.InitializeAuthModule(auth.AuthModuleConfig{
		DB:                    env.DB,
		Redis:                 env.Redis,
		Logger:                logger,
		AuthConfig:            env.Config.AuthConfig,
		SMTPConfig:            env.Config.SMTPConfig,
		AccountSvc:            accountMod.Service,
		Providers:             nil,
		KeySvc:                keySvc,
		BaseURL:               "",
		Auditor:               auditor,
		TokenSvc:              tokenSvc,
		CredentialRepo:        accountMod.CredentialRepo,
		AccountRepo:           accountMod.AccountRepo,
		RoleRepo:              accountMod.RoleRepo,
		FederatedIdentityRepo: accountMod.FederatedIdentityRepo,
	})
	require.NoError(t, err)

	oauth2Mod, err := oauth2.InitializeOAuth2Module(env.DB, env.Redis, logger, env.Config.AuthConfig, auditor)
	require.NoError(t, err)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	oidcMod := oidc.InitializeOIDCModule(
		tokenSvc, accountMod.Service, env.Config.AuthConfig,
		authMod.SessionService, accountMod.CredentialRepo,
		oauth2Mod.ClientRepo, &http.Client{Timeout: 5 * time.Second}, logger,
	)

	// Wire cross-module dependencies
	roleCacheInvalidator, _ := authMod.AuthService.(accountService.RoleCacheInvalidator)
	accountMod.Service.SetOptions(&accountService.AccountServiceOptions{
		SessionRevoker:          authMod.SessionService,
		OAuth2ClientDeleter:     &oauth2ClientDeleterAdapter{clientRepo: oauth2Mod.ClientRepo},
		ConsentCacheInvalidator: oauth2Mod.ConsentService,
		RoleCacheInvalidator:    roleCacheInvalidator,
	})

	// Create controllers
	authCtrl := authController.NewAuthController(authMod.AuthService, tokenSvc, authMod.SocialLoginService, authMod.VerificationService, authMod.PasswordResetService, false, logger)

	oauth2Ctrl, err := oauth2Controller.NewOAuth2ControllerFromConfig(oauth2Controller.OAuth2ControllerConfig{
		ClientSvc:                  oauth2Mod.ClientService,
		AuthCodeSvc:                oauth2Mod.AuthCodeService,
		ConsentSvc:                 oauth2Mod.ConsentService,
		TokenSvc:                   tokenSvc,
		IDTokenSvc:                 oidcMod.IDTokenService,
		DeviceCodeSvc:              oauth2Mod.DeviceCodeService,
		ClientAuth:                 &oauth2Service.ClientAuthenticator{},
		AccountValidator:           &alwaysActiveValidator{},
		SessionValidator:           authMod.SessionService,
		Redis:                      env.Redis,
		Issuer:                     "http://localhost",
		EnforcePKCEForConfidential: false,
		Logger:                     logger,
		RoleFetcher:                &accountRoleFetcherAdapter{accountSvc: accountMod.Service},
	})
	require.NoError(t, err)

	clientCtrl := oauth2Controller.NewClientController(oauth2Mod.ClientService, logger)

	oidcCtrl := oidcController.NewOIDCController(
		oidcMod.DiscoveryService, oidcMod.JWKSService,
		oidcMod.UserInfoService, oidcMod.LogoutService,
		oauth2Mod.ClientRepo, tokenSvc, authMod.SessionService,
		"http://localhost", logger,
	)

	auditQueryRepo := auditRepository.NewAuditQueryRepository(env.DB)
	authSvcConcrete, _ := authMod.AuthService.(*authServicePkg.AuthService)
	adminCtrl := adminController.NewAdminController(accountMod.Service, oauth2Mod.ConsentService, auditQueryRepo, authSvcConcrete, logger)

	// Build Gin engine with middleware
	engine := gin.New()
	_ = engine.SetTrustedProxies([]string{"127.0.0.1"})

	corsConfig := cors.Config{
		AllowAllOrigins:  true,
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token"},
		ExposeHeaders:    []string{"X-Request-ID"},
	}

	engine.Use(
		middleware.RecoveryMiddleware(logger),
		cors.New(corsConfig),
		middleware.RequestIDMiddleware(),
		middleware.ZapLoggerMiddleware(logger),
		middleware.SecurityHeadersMiddleware(false),
		middleware.MaxBodySizeMiddleware(10<<20),
		middleware.TimeoutMiddleware(30*time.Second),
		middleware.CSRFMiddleware(false, logger, 3600,
			"/oauth2/token",
			"/oauth2/introspect",
			"/oauth2/device/code",
			"/.well-known",
			"/swagger",
		),
	)

	err = router.RegisterWebRouter(router.RouterDeps{
		Server:           engine,
		DB:               env.DB,
		AuthCtrl:         authCtrl,
		OAuth2Ctrl:       oauth2Ctrl,
		ClientCtrl:       clientCtrl,
		OIDCCtrl:         oidcCtrl,
		AdminCtrl:        adminCtrl,
		TokenSvc:         tokenSvc,
		PasskeyCtrl:      nil,
		Redis:            env.Redis,
		RateLimits:       env.Config.WebServerConfig.RateLimits,
		Debug:            true,
		SessionValidator: authMod.SessionService,
		Logger:           logger,
		MetricsEnabled:   false,
	})
	require.NoError(t, err)

	server := httptest.NewServer(engine)

	client := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Cleanup(func() {
		server.Close()
	})

	return &HTTPTestEnv{
		TestEnv:       env,
		Server:        server,
		Client:        client,
		Engine:        engine,
		TokenSvc:      tokenSvc,
		KeySvc:        keySvc,
		SessionSvc:    authMod.SessionService,
		OAuth2Ctrl:    oauth2Ctrl,
		OIDCCtrl:      oidcCtrl,
		AccountModule: accountMod,
		AuthModule:    authMod,
		OAuth2Module:  oauth2Mod,
		Issuer:        env.Config.AuthConfig.Issuer,
	}
}

// SeedOAuth2Client inserts a test OAuth2 client directly into the database.
func (e *HTTPTestEnv) SeedOAuth2Client(t *testing.T, ctx context.Context, accountID string, opts SeedClientOptions) (clientID, clientSecret string) {
	t.Helper()

	if opts.Name == "" {
		opts.Name = "Test Client"
	}
	if len(opts.GrantTypes) == 0 {
		opts.GrantTypes = []string{"authorization_code"}
	}
	if len(opts.Scopes) == 0 {
		opts.Scopes = []string{"openid", "profile", "email"}
	}

	client, err := oauth2Domain.NewOAuth2Client(accountID, opts.Name, generateTestClientID(), opts.GrantTypes)
	require.NoError(t, err)

	client.RedirectURIs = opts.RedirectURIs
	client.PostLogoutRedirectURIs = opts.PostLogoutRedirectURIs
	client.Scopes = opts.Scopes
	client.IsConfidential = opts.Confidential
	client.FrontchannelLogoutURI = opts.FrontchannelLogoutURI
	client.FrontchannelLogoutSessionRequired = opts.FrontchannelLogoutSessionRequired
	client.BackchannelLogoutURI = opts.BackchannelLogoutURI
	client.BackchannelLogoutSessionRequired = opts.BackchannelLogoutSessionRequired

	secret := ""
	if opts.Confidential {
		secret = generateTestClientSecret()
		hashedSecret, hashErr := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		require.NoError(t, hashErr)
		client.ClientSecretHash = string(hashedSecret)
	}

	_, err = e.DB.ExecContext(ctx,
		`INSERT INTO oauth2_clients (id, account_id, client_id, client_secret_hash, name, description, redirect_uris, post_logout_redirect_uris, grant_types, scopes, is_confidential, metadata, frontchannel_logout_uri, frontchannel_logout_session_required, backchannel_logout_uri, backchannel_logout_session_required)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		client.ID, client.AccountID, client.ClientID, client.ClientSecretHash,
		client.Name, client.Description,
		marshalJSON(client.RedirectURIs), marshalJSON(client.PostLogoutRedirectURIs),
		marshalJSON(client.GrantTypes), marshalJSON(client.Scopes),
		client.IsConfidential, marshalJSON(client.Metadata),
		client.FrontchannelLogoutURI, client.FrontchannelLogoutSessionRequired,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired,
	)
	require.NoError(t, err)

	return client.ClientID, secret
}

// DoRequest makes an HTTP request to the test server.
func (e *HTTPTestEnv) DoRequest(t *testing.T, method, path string, body io.Reader, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		if headers == nil {
			headers = make(map[string]string)
		}
		if headers["X-CSRF-Token"] == "" {
			headers["X-CSRF-Token"] = e.csrfToken(t)
		}
	}

	req, err := http.NewRequest(method, e.Server.URL+path, body)
	require.NoError(t, err)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.Client.Do(req)
	require.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	return resp, respBody
}

func (e *HTTPTestEnv) csrfToken(t *testing.T) string {
	t.Helper()
	serverURL, err := url.Parse(e.Server.URL)
	require.NoError(t, err)

	findToken := func() string {
		for _, cookie := range e.Client.Jar.Cookies(serverURL) {
			if cookie.Name == "csrf_token" {
				return cookie.Value
			}
		}
		return ""
	}
	if token := findToken(); token != "" {
		return token
	}

	resp, err := e.Client.Get(e.Server.URL + "/health")
	require.NoError(t, err)
	_ = resp.Body.Close()
	token := findToken()
	require.NotEmpty(t, token)
	return token
}

// DoFormRequest makes a form-encoded POST request.
func (e *HTTPTestEnv) DoFormRequest(t *testing.T, method, path string, formData map[string]string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()

	values := make([]string, 0, len(formData))
	for k, v := range formData {
		values = append(values, k+"="+v)
	}
	body := strings.NewReader(strings.Join(values, "&"))

	if headers == nil {
		headers = make(map[string]string)
	}
	if _, ok := headers["Content-Type"]; !ok {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	return e.DoRequest(t, method, path, body, headers)
}

func (e *HTTPTestEnv) DoJSONRequest(t *testing.T, method, path string, payload any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	if headers == nil {
		headers = make(map[string]string)
	}
	headers["Content-Type"] = "application/json"
	return e.DoRequest(t, method, path, strings.NewReader(string(body)), headers)
}

// DoBearerRequest makes an HTTP request with a Bearer token.
func (e *HTTPTestEnv) DoBearerRequest(t *testing.T, method, path, token string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	return e.DoRequest(t, method, path, body, map[string]string{
		"Authorization": "Bearer " + token,
	})
}

// alwaysActiveValidator implements oauth2Controller.AccountValidator for tests.
type alwaysActiveValidator struct{}

func (v *alwaysActiveValidator) IsAccountActive(_ context.Context, _ string) bool {
	return true
}

// oauth2ClientDeleterAdapter wraps clientRepo for account service.
type oauth2ClientDeleterAdapter struct {
	clientRepo oauth2Repo.OAuth2ClientRepository
}

func (a *oauth2ClientDeleterAdapter) SoftDeleteOAuth2ClientsByAccount(ctx context.Context, tx *sql.Tx, accountID string, deletedAt time.Time) error {
	return a.clientRepo.SoftDeleteByAccountID(ctx, tx, accountID, deletedAt)
}

func generateTestClientID() string {
	return "test-" + uuid.NewString()
}

func generateTestClientSecret() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 10)
	}
	return hex.EncodeToString(b)
}

func marshalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

type accountRoleFetcherAdapter struct {
	accountSvc accountService.AccountService
}

func (a *accountRoleFetcherAdapter) GetAccountRoles(ctx context.Context, accountID string) ([]string, error) {
	roles, err := a.accountSvc.GetAccountRoles(ctx, accountID)
	if err != nil {
		return nil, err
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return roleNames, nil
}
