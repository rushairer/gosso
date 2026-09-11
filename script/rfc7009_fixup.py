from pathlib import Path


def update_http_harness() -> None:
    path = Path("tests/http/httptest_helpers.go")
    text = path.read_text()
    start = text.index("middleware.CSRFMiddleware")
    end = text.index("err = router.RegisterWebRouter", start)
    block = text[start:end]
    if '"/oauth2/revoke",' in block:
        return
    lines = text.splitlines()
    token_line = "\t\t\t\"/oauth2/token\","
    for index, line in enumerate(lines):
        if line == token_line:
            lines.insert(index + 1, "\t\t\t\"/oauth2/revoke\",")
            path.write_text("\n".join(lines) + "\n")
            return
    raise RuntimeError("HTTP integration CSRF token endpoint anchor not found")


def add_http_regression() -> None:
    path = Path("tests/http/oauth2_http_integration_test.go")
    text = path.read_text()
    if "TestHTTP_TokenRevocationBasicAuthWithoutCSRF" in text:
        return
    text += r'''

// TestHTTP_TokenRevocationBasicAuthWithoutCSRF verifies the production protocol
// boundary: confidential OAuth clients authenticate revocation requests with
// client_secret_basic and never need a browser CSRF cookie/header. Repeating a
// revocation remains HTTP 200 so token validity is not disclosed (RFC 7009 §2.2).
func TestHTTP_TokenRevocationBasicAuthWithoutCSRF(t *testing.T) {
	e := setupTest(t)
	ctx := context.Background()

	accountID, err := e.SeedAccount(ctx, "revoke-basic-user", "revoke-basic@example.com", "password123")
	require.NoError(t, err)
	clientID, clientSecret := e.SeedOAuth2Client(t, ctx, accountID, SeedClientOptions{
		Confidential:     true,
		GrantTypes:       []string{"client_credentials"},
		Scopes:           []string{"openid"},
		AllowedResources: []string{testClientCredentialsResource},
	})

	tokenResp, tokenBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         "openid",
		"resource":      testClientCredentialsResource,
	}, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))
	require.NotEmpty(t, tokenResult.AccessToken)

	revokeWithoutCSRF := func() *http.Response {
		body := strings.NewReader("token=" + tokenResult.AccessToken + "&token_type_hint=access_token")
		req, reqErr := http.NewRequest(http.MethodPost, e.Server.URL+"/oauth2/revoke", body)
		require.NoError(t, reqErr)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		resp, doErr := e.Client.Do(req)
		require.NoError(t, doErr)
		return resp
	}

	resp := revokeWithoutCSRF()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	introResp, introBody := e.DoFormRequest(t, http.MethodPost, "/oauth2/introspect", map[string]string{
		"token":         tokenResult.AccessToken,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, nil)
	require.Equal(t, http.StatusOK, introResp.StatusCode)
	var intro struct {
		Active bool `json:"active"`
	}
	require.NoError(t, json.Unmarshal(introBody, &intro))
	assert.False(t, intro.Active)

	resp = revokeWithoutCSRF()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
}
'''
    path.write_text(text)


def update_release_metadata() -> None:
    changelog = Path("CHANGELOG.md")
    text = changelog.read_text()
    if "## [1.6.1] - 2026-09-11" not in text:
        marker = "## [1.6.0] - 2026-09-11"
        release = """## [1.6.1] - 2026-09-11

### Fixed
- Exempt the OAuth 2.0 revocation endpoint from browser double-submit CSRF so confidential clients can use RFC 6749 `client_secret_basic` as advertised by OIDC discovery.
- Preserve RFC 7009 non-disclosure semantics by allowing repeated revocation requests for already-invalid tokens to reach the revocation controller and return HTTP 200 after successful client authentication.

### Security
- Keep browser/session logout endpoints under CSRF protection; only the non-browser OAuth protocol endpoint `/oauth2/revoke` joins the existing token, introspection, and device-authorization CSRF exclusions.

"""
        if marker not in text:
            raise RuntimeError("CHANGELOG 1.6.0 marker not found")
        changelog.write_text(text.replace(marker, release + marker, 1))

    chart = Path("deploy/helm/gosso/Chart.yaml")
    text = chart.read_text()
    text = text.replace("version: 1.6.0", "version: 1.6.1", 1)
    text = text.replace('appVersion: "1.6.0"', 'appVersion: "1.6.1"', 1)
    chart.write_text(text)


if __name__ == "__main__":
    update_http_harness()
    add_http_regression()
    update_release_metadata()
