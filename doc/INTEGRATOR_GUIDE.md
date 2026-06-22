# Integrator Guide

How to connect your application to gosso as an OpenID Connect (OIDC) identity provider.

> [中文版本](INTEGRATOR_GUIDE.zh-CN.md)

---

## Quick Start

gosso is a standards-compliant OIDC Provider. Any library that supports OpenID Connect can connect to it — no SDK required.

### 1. Discover the OIDC Configuration

```
GET https://sso.example.com/.well-known/openid-configuration
```

This returns the discovery document with all endpoint URLs, supported scopes, and signing algorithms.

### 2. Register an OAuth2 Client

```bash
curl -X POST https://sso.example.com/api/oauth2/clients \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"],
    "is_confidential": true
  }'
```

Save the returned `client_id` and `client_secret`.

### 3. Implement the Authorization Code Flow

See the language-specific examples below.

---

## Go

Using the standard `golang.org/x/oauth2` package:

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// OIDC endpoints (from discovery document)
var (
	issuer       = "https://sso.example.com"
	clientID     = "your-client-id"
	clientSecret = "your-client-secret"
	redirectURI  = "https://app.example.com/callback"
)

var oauth2Config = &oauth2.Config{
	ClientID:     clientID,
	ClientSecret: clientSecret,
	RedirectURL:  redirectURI,
	Scopes:       []string{"openid", "profile", "email"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  issuer + "/oauth2/authorize",
		TokenURL: issuer + "/oauth2/token",
	},
}

// Step 1: Generate authorization URL
func authURL(state string) string {
	return oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Step 2: Exchange authorization code for tokens
func exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return oauth2Config.Exchange(ctx, code)
}

// Step 3: Get user info
func userInfo(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	client := oauth2Config.Client(ctx, token)
	resp, err := client.Get(issuer + "/oidc/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info map[string]interface{}
	return info, json.NewDecoder(resp.Body).Decode(&info)
}
```

### Token Validation (Go)

```go
import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/MicahParks/keyfunc/v3"
)

// Fetch JWKS and create a keyfunc
jwks, err := keyfunc.NewDefaultCtx(ctx, []string{issuer + "/.well-known/jwks.json"))
if err != nil {
	log.Fatal(err)
}

// Parse and validate the token
token, err := jwt.Parse(accessToken, jwks.Keyfunc,
	jwt.WithAudience(clientID),
	jwt.WithIssuer(issuer),
)
if err != nil {
	log.Printf("Token invalid: %v", err)
}

claims := token.Claims.(jwt.MapClaims)
sub := claims["sub"].(string) // account ID
```

### Client Credentials (Go)

For machine-to-machine authentication:

```go
creds := &clientcredentials.Config{
	ClientID:     clientID,
	ClientSecret: clientSecret,
	TokenURL:     issuer + "/oauth2/token",
	Scopes:       []string{"openid"},
}

token, err := creds.Token(ctx)
```

---

## JavaScript / Node.js

Using the `openid-client` library:

```bash
npm install openid-client
```

```javascript
import { Issuer, generators } from 'openid-client';

// Step 1: Discover the issuer
const gosso = await Issuer.discover('https://sso.example.com');
console.log('Discovered:', gosso.issuer);

// Step 2: Create client
const client = new gosso.Client({
  client_id: 'your-client-id',
  client_secret: 'your-client-secret',
  redirect_uris: ['https://app.example.com/callback'],
  response_types: ['code'],
});

// Step 3: Generate authorization URL
const codeVerifier = generators.codeVerifier();
const codeChallenge = generators.codeChallenge(codeVerifier);
const state = generators.state();

const authUrl = client.authorizationUrl({
  scope: 'openid profile email',
  state,
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
});

// Step 4: Handle callback
const params = client.callbackParams(req);
const tokenSet = await client.callback(
  'https://app.example.com/callback',
  params,
  { state, code_verifier: codeVerifier }
);

console.log('Access Token:', tokenSet.access_token);
console.log('ID Token claims:', tokenSet.claims());

// Step 5: Get user info
const userinfo = await client.userinfo(tokenSet.access_token);
console.log('User:', userinfo);
```

---

## Python

Using the `authlib` library:

```bash
pip install authlib requests
```

```python
from authlib.integrations.requests_client import OAuth2Session

issuer = "https://sso.example.com"
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_uri = "https://app.example.com/callback"

# Step 1: Create OAuth2 session
oauth = OAuth2Session(
    client_id=client_id,
    client_secret=client_secret,
    redirect_uri=redirect_uri,
    scope="openid profile email",
)

# Step 2: Generate authorization URL
authorization_url, state = oauth.create_authorization_url(
    f"{issuer}/oauth2/authorize"
)
print(f"Visit: {authorization_url}")

# Step 3: Exchange code for tokens
token = oauth.fetch_token(
    f"{issuer}/oauth2/token",
    authorization_response=callback_url,
)

# Step 4: Get user info
userinfo = oauth.get(f"{issuer}/oidc/userinfo").json()
print(f"User: {userinfo['sub']}, Email: {userinfo.get('email')}")
```

### Token Validation (Python)

```python
import jwt
import requests

jwks = requests.get(f"{issuer}/.well-known/jwks.json").json()

# Decode and validate
claims = jwt.decode(
    access_token,
    jwks,
    algorithms=["RS256"],
    audience=client_id,
    issuer=issuer,
)
print(f"Account ID: {claims['sub']}")
```

---

## Token Refresh

All clients should handle token expiry gracefully. The refresh token grant is:

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<token>&client_id=<id>&client_secret=<secret>
```

Response:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

> **Note**: Refresh tokens are rotated on each use. Store the new refresh token.

---

## PKCE (Public Clients)

For mobile apps and SPAs that cannot keep a client secret:

1. Generate a `code_verifier` (43–128 character random string)
2. Compute `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Add `code_challenge` and `code_challenge_method=S256` to the authorization URL
4. Send `code_verifier` in the token exchange

gosso enforces S256 for public clients (no `plain`).

---

## Device Code Flow (RFC 8628)

For devices without a browser (smart TVs, CLI tools):

```
POST /oauth2/device/code
Content-Type: application/x-www-form-urlencoded

client_id=<id>&scope=openid+profile
```

Response:

```json
{
  "device_code": "abc...",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://sso.example.com/oauth2/device",
  "verification_uri_complete": "https://sso.example.com/oauth2/device?user_code=ABCD-EFGH",
  "expires_in": 600,
  "interval": 5
}
```

Poll `POST /oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=<code>` until the user approves.

---

## Error Handling

gosso returns standard OAuth2 errors:

| Error | HTTP | Description |
|-------|------|-------------|
| `invalid_request` | 400 | Missing or invalid parameters |
| `invalid_client` | 401 | Invalid client credentials |
| `invalid_grant` | 400 | Invalid or expired code/token |
| `unauthorized_client` | 403 | Client not authorized for this grant type |
| `unsupported_grant_type` | 400 | Grant type not supported |
| `invalid_scope` | 400 | Requested scope not allowed |

Rate limiting returns `429` with `Retry-After` header.

---

## Scopes

| Scope | Claims Returned |
|-------|----------------|
| `openid` | `sub` (account ID) |
| `profile` | `name`, `preferred_username`, `locale`, `zoneinfo`, `updated_at` |
| `email` | `email`, `email_verified` |

---

## JWKS Rotation

gosso rotates signing keys periodically. Always fetch the JWKS from `/.well-known/jwks.json` and cache it. Use the `kid` (key ID) header in JWTs to select the correct key.

Recommended caching strategy:
- Fetch JWKS on first token validation
- Cache for 24 hours
- On `kid` miss, re-fetch JWKS (key may have rotated)
- If still missing, reject the token
