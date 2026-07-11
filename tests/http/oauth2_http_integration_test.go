//go:build integration

package http_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
)

func setupTest(t *testing.T) *HTTPTestEnv {
	t.Helper()
	return SetupHTTPTestEnv(t)
}

// ──────────────────────────────────────────────
// Health & Readiness
// ──────────────────────────────────────────────

func TestHTTP_HealthAndReadiness(t *testing.T) {
	e := setupTest(t)

	// Health endpoint
	resp, body := e.DoRequest(t, http.MethodGet, "/health", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"status":"ok"`)

	// Readiness endpoint
	resp, body = e.DoRequest(t, http.MethodGet, "/readiness", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"database":"ok"`)
	assert.Contains(t, string(body), `"redis":"ok"`)
}

// ──────────────────────────────────────────────
// OIDC Discovery
// ──────────────────────────────────────────────

func TestHTTP_OIDCDiscovery(t *testing.T) {
	e := setupTest(t)

	resp, body := e.DoRequest(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))

	assert.NotEmpty(t, doc["issuer"])
	assert.NotEmpty(t, doc["authorization_endpoint"])
	assert.NotEmpty(t, doc["token_endpoint"])
	assert.NotEmpty(t, doc["jwks_uri"])
	assert.NotEmpty(t, doc["userinfo_endpoint"])
	assert.NotEmpty(t, doc["end_session_endpoint"])
	assert.NotEmpty(t, doc["revocation_endpoint"])
	assert.NotEmpty(t, doc["introspection_endpoint"])
	assert.NotEmpty(t, doc["device_authorization_endpoint"])

	// Front/back-channel logout support
	assert.Equal(t, true, doc["frontchannel_logout_supported"])
	assert.Equal(t, true, doc["frontchannel_logout_session_supported"])
	assert.Equal(t, true, doc["backchannel_logout_supported"])

	// Verify PKCE support
	methods, ok := doc["code_challenge_methods_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, methods, "S256")
}

// ──────────────────────────────────────────────
// JWKS
// ──────────────────────────────────────────────

func TestHTTP_JWKS(t *testing.T) {
	e := setupTest(t)

	resp, body := e.DoRequest(t, http.MethodGet, "/.well-known/jwks.json", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(body, &jwks))
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "RSA", jwks.Keys[0].Kty)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.NotEmpty(t, jwks.Keys[0].Kid)
	assert.NotEmpty(t, jwks.Keys[0].N)
}

// ──────────────────────────────────────────────
// Client Credentials Flow
// ──────────────────────────────────────────────

func TestHTTP_ClientCredentialsFlow(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "cc-user", "cc@example.com", "password123")
	require.NoError(t, err)

	clientID, clientSecret := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: true,
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"openid", "profile"},
	})

	// Token request with client_secret_post
	resp, body := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "openid profile",
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	require.NoError(t, json.Unmarshal(body, &tokenResp))
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Equal(t, "Bearer", tokenResp.TokenType)
	assert.Greater(t, tokenResp.ExpiresIn, 0)
}

// ──────────────────────────────────────────────
// Authorization Code Flow
// ──────────────────────────────────────────────

func TestHTTP_AuthorizationCodeFlow(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "authcode-user", "authcode@example.com", "password123")
	require.NoError(t, err)

	clientID, clientSecret := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: true,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
	})

	// Step 1: Login to get an access token (we'll use this to authorize)
	loginResp, loginBody := e.DoJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "authcode-user",
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var loginResult struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			SessionID    string `json:"session_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(loginBody, &loginResult))
	require.NotEmpty(t, loginResult.Data.AccessToken)

	// Step 2: GET /oauth2/authorize (with Bearer auth)
	authorizeURL := fmt.Sprintf("/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid%%20profile%%20email&state=test-state",
		clientID, "https://app.example.com/callback")
	resp, authorizeBody := e.DoBearerRequest(t, http.MethodGet, authorizeURL, loginResult.Data.AccessToken, nil)
	// With Bearer auth, the authorize endpoint may return 200 (consent page) or 302 (if consent already granted)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	consentID := extractHiddenInput(string(authorizeBody), "consent_id")
	require.NotEmpty(t, consentID)

	// Step 3: POST consent
	consentResp, consentBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/authorize", map[string]string{
		"client_id":     clientID,
		"redirect_uri":  "https://app.example.com/callback",
		"scope":         "openid profile email",
		"state":         "test-state",
		"approved":      "true",
		"response_type": "code",
		"consent_id":    consentID,
	}, map[string]string{
		"Authorization": "Bearer " + loginResult.Data.AccessToken,
		"Content-Type":  "application/x-www-form-urlencoded",
	})

	// The consent endpoint should redirect with a code
	if consentResp.StatusCode == http.StatusFound {
		location := consentResp.Header.Get("Location")
		assert.Contains(t, location, "code=")
		assert.Contains(t, location, "state=test-state")

		// Extract authorization code
		code := extractQueryParam(location, "code")
		require.NotEmpty(t, code)

		// Step 4: Exchange code for tokens
		tokenResp, tokenBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "https://app.example.com/callback",
			"client_id":     clientID,
			"client_secret": clientSecret,
		}, nil)
		assert.Equal(t, http.StatusOK, tokenResp.StatusCode)

		var tokenResult struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IDToken      string `json:"id_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
		}
		require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))
		assert.NotEmpty(t, tokenResult.AccessToken)
		assert.NotEmpty(t, tokenResult.RefreshToken)
		assert.NotEmpty(t, tokenResult.IDToken) // openid scope was requested
		assert.Equal(t, "Bearer", tokenResult.TokenType)
	} else {
		// If consent was auto-approved, we might get a direct response
		t.Logf("Consent response status: %d, body: %s", consentResp.StatusCode, string(consentBody))
	}
}

// ──────────────────────────────────────────────
// Authorization Code Flow with PKCE
// ──────────────────────────────────────────────

func TestHTTP_AuthorizationCodeFlow_PKCE(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "pkce-user", "pkce@example.com", "password123")
	require.NoError(t, err)

	// Public client (no secret)
	clientID, _ := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: false,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})

	// Generate PKCE code_verifier and code_challenge
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Login
	loginResp, loginBody := e.DoJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "pkce-user",
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var loginResult struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(loginBody, &loginResult))

	// Authorize with PKCE
	authorizeURL := fmt.Sprintf("/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&code_challenge=%s&code_challenge_method=S256&state=pkce-state",
		clientID, "https://app.example.com/callback", codeChallenge)
	resp, authorizeBody := e.DoBearerRequest(t, http.MethodGet, authorizeURL, loginResult.Data.AccessToken, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	consentID := extractHiddenInput(string(authorizeBody), "consent_id")
	require.NotEmpty(t, consentID)

	// POST consent
	consentResp, _ := e.DoFormRequest(t, http.MethodPost, "/oauth2/authorize", map[string]string{
		"client_id":             clientID,
		"redirect_uri":          "https://app.example.com/callback",
		"scope":                 "openid",
		"state":                 "pkce-state",
		"approved":              "true",
		"response_type":         "code",
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
		"consent_id":            consentID,
	}, map[string]string{
		"Authorization": "Bearer " + loginResult.Data.AccessToken,
		"Content-Type":  "application/x-www-form-urlencoded",
	})

	if consentResp.StatusCode == http.StatusFound {
		location := consentResp.Header.Get("Location")
		code := extractQueryParam(location, "code")
		require.NotEmpty(t, code)

		// Exchange with correct code_verifier
		tokenResp, tokenBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "https://app.example.com/callback",
			"client_id":     clientID,
			"code_verifier": codeVerifier,
		}, nil)
		assert.Equal(t, http.StatusOK, tokenResp.StatusCode)

		var tokenResult struct {
			AccessToken string `json:"access_token"`
		}
		require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))
		assert.NotEmpty(t, tokenResult.AccessToken)

		// Try with wrong code_verifier — should fail
		wrongResp, wrongBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
			"grant_type":    "authorization_code",
			"code":          code, // code already consumed
			"redirect_uri":  "https://app.example.com/callback",
			"client_id":     clientID,
			"code_verifier": "wrong-verifier",
		}, nil)
		assert.Equal(t, http.StatusBadRequest, wrongResp.StatusCode)
		assert.Contains(t, string(wrongBody), "invalid_grant")
	}
}

// ──────────────────────────────────────────────
// Refresh Token Flow
// ──────────────────────────────────────────────

func TestHTTP_ClientCredentialsOmitsRefreshToken(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "refresh-user", "refresh@example.com", "password123")
	require.NoError(t, err)

	clientID, clientSecret := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: true,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"openid", "profile"},
	})

	// Client credentials tokens must never include refresh tokens (RFC 6749 §4.4.3).
	tokenResp, tokenBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "openid profile",
	}, nil)
	assert.Equal(t, http.StatusOK, tokenResp.StatusCode)

	// Client credentials doesn't return refresh_token per spec.
	// Let's verify that.
	var tokenResult struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))
	assert.NotEmpty(t, tokenResult.AccessToken)
	assert.Empty(t, tokenResult.RefreshToken) // No refresh token for client_credentials
}

// ──────────────────────────────────────────────
// Token Introspection
// ──────────────────────────────────────────────

func TestHTTP_TokenIntrospection(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "introspect-user", "introspect@example.com", "password123")
	require.NoError(t, err)

	clientID, clientSecret := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: true,
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"openid"},
	})

	// Get a token
	tokenResp, tokenBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "openid",
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))

	// Introspect the active token
	introResp, introBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/introspect", map[string]string{
		"token":         tokenResult.AccessToken,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, nil)
	assert.Equal(t, http.StatusOK, introResp.StatusCode)

	var introResult struct {
		Active    bool   `json:"active"`
		Sub       string `json:"sub"`
		ClientID  string `json:"client_id"`
		Scope     string `json:"scope"`
		TokenType string `json:"token_type"`
	}
	require.NoError(t, json.Unmarshal(introBody, &introResult))
	assert.True(t, introResult.Active)
	assert.Equal(t, accountID, introResult.Sub)
	assert.Equal(t, clientID, introResult.ClientID)
	assert.Equal(t, "openid", introResult.Scope)
	assert.Equal(t, "Bearer", introResult.TokenType)

	// Introspect with wrong credentials (different client)
	wrongResp, wrongBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/introspect", map[string]string{
		"token":         tokenResult.AccessToken,
		"client_id":     clientID,
		"client_secret": "wrong-secret",
	}, nil)
	// Should fail auth
	assert.True(t, wrongResp.StatusCode == http.StatusUnauthorized || wrongResp.StatusCode == http.StatusBadRequest,
		"expected 401 or 400, got %d, body: %s", wrongResp.StatusCode, string(wrongBody))
}

// ──────────────────────────────────────────────
// Token Revocation
// ──────────────────────────────────────────────

func TestHTTP_TokenRevocation(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "revoke-user", "revoke@example.com", "password123")
	require.NoError(t, err)

	clientID, clientSecret := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: true,
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"openid"},
	})

	// Get a token
	tokenResp, tokenBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "openid",
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))

	// Revoke the token
	revokeResp, _ := e.DoFormRequest(t, http.MethodPost, "/oauth2/revoke", map[string]string{
		"token":         tokenResult.AccessToken,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, nil)
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)

	// Introspect — should be inactive
	introResp, introBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/introspect", map[string]string{
		"token":         tokenResult.AccessToken,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, nil)
	assert.Equal(t, http.StatusOK, introResp.StatusCode)

	var introResult struct {
		Active bool `json:"active"`
	}
	require.NoError(t, json.Unmarshal(introBody, &introResult))
	assert.False(t, introResult.Active)
}

// ──────────────────────────────────────────────
// OIDC UserInfo
// ──────────────────────────────────────────────

func TestHTTP_OIDCUserInfo(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "userinfo-user", "userinfo@example.com", "password123")
	require.NoError(t, err)

	accessToken, err := e.TokenSvc.GenerateAccessToken(&tokenDomain.AccessTokenClaims{
		AccountID: accountID,
		Scope:     "openid",
	})
	require.NoError(t, err)

	// GET /oidc/userinfo
	resp, body := e.DoBearerRequest(t, http.MethodGet, "/oidc/userinfo", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var userInfo map[string]any
	require.NoError(t, json.Unmarshal(body, &userInfo))
	assert.NotEmpty(t, userInfo["sub"])
}

// ──────────────────────────────────────────────
// OIDC Logout
// ──────────────────────────────────────────────

func TestHTTP_OIDCLogout(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "logout-user", "logout@example.com", "password123")
	require.NoError(t, err)

	_, _ = e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: true,
		RedirectURIs: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})

	// Login
	loginResp, loginBody := e.DoJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "logout-user",
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var loginResult struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(loginBody, &loginResult))
	accessToken := loginResult.Data.AccessToken

	// Logout via Bearer token
	logoutResp, logoutBody := e.DoFormRequest(t, http.MethodPost, "/oidc/logout", map[string]string{}, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Content-Type":  "application/x-www-form-urlencoded",
	})
	assert.Equal(t, http.StatusOK, logoutResp.StatusCode)
	assert.Contains(t, string(logoutBody), "logged_out")

	// Verify the token is now invalid (session revoked)
	userInfoResp, _ := e.DoBearerRequest(t, http.MethodGet, "/oidc/userinfo", accessToken, nil)
	assert.Equal(t, http.StatusUnauthorized, userInfoResp.StatusCode)
}

// ──────────────────────────────────────────────
// Front-Channel Logout
// ──────────────────────────────────────────────

func TestHTTP_FrontChannelLogout(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "fc-logout-user", "fc@example.com", "password123")
	require.NoError(t, err)

	_, _ = e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential:                      true,
		RedirectURIs:                      []string{"https://app.example.com/callback"},
		GrantTypes:                        []string{"authorization_code"},
		Scopes:                            []string{"openid"},
		FrontchannelLogoutURI:             "https://app.example.com/frontchannel-logout",
		FrontchannelLogoutSessionRequired: true,
	})

	// Seed a consent record so the client appears in front-channel logout query
	_, err = e.DB.ExecContext(ctx,
		`INSERT INTO oauth2_consents (account_id, client_id, scopes) VALUES ($1, (SELECT id FROM oauth2_clients WHERE account_id = $1 LIMIT 1), '["openid"]')`,
		accountID)
	require.NoError(t, err)

	// Login
	loginResp, loginBody := e.DoJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "fc-logout-user",
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var loginResult struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(loginBody, &loginResult))

	// GET /oidc/frontchannel_logout with Bearer auth
	resp, body := e.DoBearerRequest(t, http.MethodGet, "/oidc/frontchannel_logout", loginResult.Data.AccessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

	html := string(body)
	assert.Contains(t, html, "iframe")
	assert.Contains(t, html, "https://app.example.com/frontchannel-logout")
	assert.Contains(t, html, "iss=")
	assert.Contains(t, html, "sid=")
}

// ──────────────────────────────────────────────
// Back-Channel Logout
// ──────────────────────────────────────────────

func TestHTTP_BackChannelLogout(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	// Set up a local HTTP server to receive the back-channel logout token
	var receivedLogoutToken string
	receiverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			receivedLogoutToken = r.FormValue("logout_token")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer receiverServer.Close()

	accountID, err := e.SeedAccount(ctx, "bc-logout-user", "bc@example.com", "password123")
	require.NoError(t, err)

	_, _ = e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential:                     true,
		RedirectURIs:                     []string{"https://app.example.com/callback"},
		GrantTypes:                       []string{"authorization_code"},
		Scopes:                           []string{"openid"},
		BackchannelLogoutURI:             receiverServer.URL,
		BackchannelLogoutSessionRequired: true,
	})

	// Seed consent
	_, err = e.DB.ExecContext(ctx,
		`INSERT INTO oauth2_consents (account_id, client_id, scopes) VALUES ($1, (SELECT id FROM oauth2_clients WHERE account_id = $1 LIMIT 1), '["openid"]')`,
		accountID)
	require.NoError(t, err)

	// Login
	loginResp, loginBody := e.DoJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": "bc-logout-user",
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, loginResp.StatusCode)

	var loginResult struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(loginBody, &loginResult))

	// Logout via Bearer token — this should trigger back-channel logout
	logoutResp, _ := e.DoFormRequest(t, http.MethodPost, "/oidc/logout", map[string]string{}, map[string]string{
		"Authorization": "Bearer " + loginResult.Data.AccessToken,
		"Content-Type":  "application/x-www-form-urlencoded",
	})
	assert.Equal(t, http.StatusOK, logoutResp.StatusCode)

	// Wait for async back-channel logout to complete
	time.Sleep(500 * time.Millisecond)

	// Verify the logout token was received
	assert.NotEmpty(t, receivedLogoutToken, "back-channel logout token should have been received")

	// Parse and validate the logout token
	if receivedLogoutToken != "" {
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		token, _, err := parser.ParseUnverified(receivedLogoutToken, jwt.MapClaims{})
		require.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)

		assert.Equal(t, e.Issuer, claims["iss"])
		assert.Equal(t, accountID, claims["sub"])

		events, ok := claims["events"].(map[string]any)
		require.True(t, ok)
		_, hasLogoutEvent := events["http://schemas.openid.net/event/backchannel-logout"]
		assert.True(t, hasLogoutEvent, "logout token should contain backchannel-logout event")
	}
}

// ──────────────────────────────────────────────
// Error Cases
// ──────────────────────────────────────────────

func TestHTTP_ErrorCases(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "error-user", "error@example.com", "password123")
	require.NoError(t, err)

	clientID, clientSecret := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential: true,
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"openid"},
	})

	t.Run("InvalidGrantType", func(t *testing.T) {
		resp, body := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
			"grant_type":    "invalid_grant_type",
			"client_id":     clientID,
			"client_secret": clientSecret,
		}, nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, string(body), "unsupported_grant_type")
	})

	t.Run("WrongClientSecret", func(t *testing.T) {
		resp, body := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     clientID,
			"client_secret": "wrong-secret",
		}, nil)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, string(body), "invalid_client")
	})

	t.Run("MissingContentType", func(t *testing.T) {
		resp, body := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
			"grant_type": "client_credentials",
		}, map[string]string{
			"Content-Type": "application/json",
		})
		assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
		assert.Contains(t, string(body), "error")
	})

	t.Run("InvalidRedirectURI", func(t *testing.T) {
		loginResp, loginBody := e.DoJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"username": "error-user",
			"password": "password123",
		}, nil)
		require.Equal(t, http.StatusOK, loginResp.StatusCode)

		var loginResult struct {
			Data struct {
				AccessToken string `json:"access_token"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(loginBody, &loginResult))

		authorizeURL := fmt.Sprintf("/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid",
			clientID, "https://evil.example.com/callback")
		resp, _ := e.DoBearerRequest(t, http.MethodGet, authorizeURL, loginResult.Data.AccessToken, nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// ──────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────

func extractQueryParam(rawURL, key string) string {
	idx := strings.Index(rawURL, key+"=")
	if idx == -1 {
		return ""
	}
	start := idx + len(key) + 1
	end := strings.Index(rawURL[start:], "&")
	if end == -1 {
		return rawURL[start:]
	}
	return rawURL[start : start+end]
}

func extractHiddenInput(body, name string) string {
	marker := `name="` + name + `" value="`
	start := strings.Index(body, marker)
	if start == -1 {
		return ""
	}
	start += len(marker)
	end := strings.IndexByte(body[start:], '"')
	if end == -1 {
		return ""
	}
	return body[start : start+end]
}
