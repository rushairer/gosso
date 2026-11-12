# GOSSO OIDC / OAuth 2.0 Integrator Guide

**Current implementation reference — 2026-11-12.** This guide replaces older copy-and-paste examples that lacked PKCE/state/nonce checks, confused OAuth resource audiences with client IDs, used an obsolete `openid-client` API, or printed provider tokens. The earlier examples remain available in Git history, not as active integration instructions.

> [中文概览](../README.zh-CN.md) · [OpenAPI](openapi.yaml) · [GOSSO source routes](../router/web.go) · [Gouno Blog confidential BFF reference](https://github.com/rushairer/gouno-blog/blob/main/docs/architecture/README.md)

## Which architecture should I choose?

For a browser-facing application with a trusted backend, **prefer a confidential Backend for Frontend (BFF)**. The browser performs top-level navigation to the application's same-origin BFF login endpoint; all authorization-code exchange, ID Token verification, refresh/revoke and OAuth token storage occur on the server. Only an opaque, host-only, Secure/HttpOnly application session Cookie reaches browser JavaScript's origin.

The Gouno Blog implementation is an audited **source example**, not an independent product-standard mandate:

- [OAuth client, PKCE, callback and ID Token verification](https://github.com/rushairer/gouno-blog/blob/main/blog-backend/internal/authbff/client.go)
- [Session endpoints and Cookie projection](https://github.com/rushairer/gouno-blog/blob/main/blog-backend/internal/authbff/http.go)
- [Encrypted Redis session storage](https://github.com/rushairer/gouno-blog/blob/main/blog-backend/internal/authbff/store.go)
- [Browser SDK in BFF mode](https://github.com/rushairer/gouno-blog/blob/main/blog-frontend/src/auth.ts)

For standalone public SPAs or mobile applications, use an up-to-date, standards-conforming OAuth/OIDC client library, enforce Authorization Code + PKCE S256, and implement explicit token/storage/origin/XSS security controls. **Do not use the Blog's confidential client secret from browser code.**

## Discover and register a client

1. Read the provider's discovery document at `GET https://sso.example.com/.well-known/openid-configuration`; use the returned endpoints and supported capabilities rather than hard-coded URLs.
2. Register a client through the authenticated GOSSO user API **`POST /api/v1/oauth2/clients`** or administrator API **`POST /api/v1/admin/oauth2/clients`** using the identity administrator UI or authorized API. These routes are confirmed in `router/web.go` and `internal/oauth2/controller/client_controller.go`. They require the appropriate logged-in GOSSO session/roles and CSRF controls; they are **not public bootstrap endpoints**.
3. Configure exact HTTPS `redirect_uris`, `post_logout_redirect_uris` and `allowed_resources` where applicable; choose `grant_types`, `scopes` and `is_confidential` consistent with your client type. Store confidential credentials in the backend's secret management system, never a Vite/browser build variable.

Example **registration request shape** (send only through an already authenticated authorized API client):

```json
{
  "name": "Example Confidential Web BFF",
  "redirect_uris": ["https://app.example.com/api/auth/callback"],
  "post_logout_redirect_uris": ["https://app.example.com/api/auth/logout/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email"],
  "allowed_resources": ["https://app.example.com/api"],
  "is_confidential": true
}
```

## Browser authorization-code flow — BFF example

1. BFF generates cryptographically random one-time `state`, `nonce` and `code_verifier` in a bounded, server-side login transaction; derives an S256 `code_challenge`.
2. BFF redirects the browser to the discovered authorization endpoint (`/oauth2/authorize`), sending `response_type=code`, registered `client_id`/`redirect_uri`, `scope`, `state`, `nonce`, `code_challenge_method=S256` and the exact RFC 8707 `resource` selected for this API.
3. GOSSO manages credentials, identity sessions, consent and any required MFA on the issuer origin. Application login forms must not impersonate the IdP.
4. Browser is redirected to the **registered application backend callback**. Backend atomically consumes the flow, checks `state` and authorization response issuer (`iss`, RFC 9207), and exchanges `code` with `code_verifier` **server-to-server** using confidential-client authentication.
5. Verify the ID Token cryptographically using discovery/JWKS, including signature and approved algorithm, exact issuer, client audience, expiration and one-time `nonce`. Do not accept decoded but unverified claims.
6. Store provider tokens only in encrypted, access-controlled server session storage, rotate/revoke them on refresh/logout, enforce an absolute session lifetime, and set a host-only Secure/HttpOnly application Cookie.
7. Application APIs must authorize against their **own permission model** and intended resource audience. Never grant a Blog permission solely from a GOSSO global administrative role or OIDC `scope`.

For browser unsafe HTTP methods, enforce same-origin CSRF protection; neither `SameSite` alone nor a JavaScript-visible OAuth token is a replacement for a well-defined session CSRF policy. Back-channel logout needs cryptographically verified logout tokens and replay protection.

## Token validation, resource indicators and UserInfo

- `/.well-known/jwks.json` exposes signing public keys; honor response cache metadata and re-fetch on unknown `kid`/rotation. Do **not** use an arbitrary hard-coded 24-hour cache validity. Validate the JWT type, allowed algorithm, issuer, expiration, audience/resource, token principal class and any client binding required by your API.
- An **ID Token** is validated for the OAuth/OIDC client and conveys the authenticated subject; it is **not** a generic authorization token for a foreign resource server.
- An **access token** is intended for the selected RFC 8707 `resource`/audience, which is not necessarily the OAuth client ID. Machine `client_credentials` tokens are not user-session principals and must not inherit an account's admin roles.
- `/oidc/userinfo` is an identity-provider resource endpoint; its current controller requires an appropriate GOSSO API audience and user principal. Do not assume a Blog-audience access token can be used to call GOSSO UserInfo.
- For cache keys and user identity, use the verified `(issuer, subject)` pair and explicit migration/alias approval where issuers change; a plain `sub` string is insufficient across issuers.

## Other supported protocol families

- `/oauth2/token` handles registered grants and confidential client authentication; refresh-token rotation is security-sensitive and must be stored atomically. Use discovery and a supported library rather than assembling untested HTTP forms.
- `/oauth2/revoke` provides RFC 7009 token revocation; treat idempotent successful revocation correctly, without disclosing whether a token previously existed.
- `/oauth2/introspect` implements token introspection for authorized clients.
- `/oauth2/device/code` and `/oauth2/device` support a device-authorization workflow for constrained devices. Implement polling/backoff and expiration from the actual response and RFC 8628 rather than a fixed sample code or interval.
- `/oidc/logout` provides RP-initiated logout, subject to registered redirect URI and CSRF/session requirements. GOSSO supports front-channel and back-channel logout contracts; validate your chosen integration in a representative environment.

## Operational verification checklist

- Exact issuer and registered URLs; no open redirects or unregistered post-logout destinations.
- Browser never receives confidential secrets or server-held provider tokens.
- PKCE/state/nonce, signed token verification, resource/audience separation, consent, MFA and permissions.
- CSRF, Cookie attributes, refresh/logout races, revocation, replay protection and incident key rotation.
- Strict CORS origin allowlists only when actually necessary; avoid cross-domain bearer-token handoff.
- TLS, clock skew, request limits, rate limits, structured logs without secrets, operational runbooks and recovery tests.

For present behavior, always compare this guide against the current Gosso controller/service code, [OpenAPI](openapi.yaml) and the exact deployed release. The reference implementation is not a certification of your application's environment.
