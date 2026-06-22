# API Versioning Strategy

本文档定义 gosso API 的版本化策略。

## Endpoint Categories

gosso exposes two categories of endpoints that follow different versioning rules:

### 1. Protocol Endpoints (no versioning)

OAuth 2.0 and OpenID Connect protocol endpoints follow their respective RFC specifications and are **not** versioned under `/api/v1/`. Breaking changes to these endpoints would only occur if the underlying RFC is updated.

| Prefix | Specification | Examples |
|--------|--------------|----------|
| `/oauth2/*` | [RFC 6749](https://tools.ietf.org/html/rfc6749) | `/oauth2/token`, `/oauth2/authorize`, `/oauth2/revoke` |
| `/.well-known/*` | [RFC 8414](https://tools.ietf.org/html/rfc8414) | `/.well-known/openid-configuration`, `/.well-known/jwks.json` |
| `/oidc/*` | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | `/oidc/userinfo`, `/oidc/logout` |
| `/health`, `/readiness` | Infrastructure | Health check endpoints |

### 2. Management API (versioned)

Management and authentication endpoints are versioned using URI path prefix:

| Prefix | Description |
|--------|-------------|
| `/api/v1/auth/*` | Authentication flows (login, MFA, passkey, social login) |
| `/api/v1/oauth2/clients` | OAuth2 client registration and management |
| `/api/v1/admin/*` | Account administration |

## Versioning Rules

- **Breaking changes** require a new version prefix (e.g., `/api/v2/`)
- **Non-breaking additions** (new fields, new endpoints) are added to the current version
- **Backward-compatible redirects** from `/api/*` to `/api/v1/*` are provided during the transition period (HTTP 308)

## Deprecation Policy

When a new API version is introduced:

1. The old version continues to function for **6 months** minimum
2. Deprecation notices are included in response headers (`Sunset: <date>`)
3. The CHANGELOG documents the deprecation timeline
4. After the sunset date, the old version returns `410 Gone`

## Current Status

| Version | Status | Introduced |
|---------|--------|------------|
| `/api/v1/` | **Current** | v1.1.0 |
