# API Stability Guarantees

This document defines the stability tiers for gosso's HTTP APIs. Operators and
SDK authors should use these tiers to assess the risk of upgrading between
versions.

## Stability Tiers

### Stable APIs

These endpoints follow Semantic Versioning. Breaking changes require a **major
version bump** (e.g., v1 → v2). Within the same major version, request/response
schemas, status codes, and error formats will not change incompatibly.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/.well-known/jwks.json` | JWKS endpoint |
| GET, POST | `/oauth2/authorize` | Authorization code flow |
| POST | `/oauth2/token` | Token exchange (code, refresh, client_credentials, device_code) |
| POST | `/oauth2/revoke` | Token revocation ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)) |
| POST | `/oauth2/introspect` | Token introspection ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)) |
| POST | `/oauth2/device/code` | Device authorization ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)) |
| GET, POST | `/oidc/userinfo` | UserInfo endpoint |
| GET | `/oidc/logout` | RP-Initiated Logout |
| POST | `/api/v1/auth/login` | Username/password login |
| POST | `/api/v1/auth/logout` | Session logout |
| POST | `/api/v1/auth/refresh` | Token refresh |
| POST | `/api/v1/auth/register` | Account registration |
| POST | `/api/v1/auth/mfa/verify` | MFA verification |
| POST | `/api/v1/auth/password/forgot` | Password reset request |
| POST | `/api/v1/auth/password/reset` | Password reset confirmation |
| GET | `/health` | Liveness probe |
| GET | `/readiness` | Readiness probe |

### Experimental APIs

These endpoints may change in minor or patch versions. They are intended for
internal administration, advanced integrations, and tooling. Use with caution in
production automation.

| Method | Path | Description |
|--------|------|-------------|
| Various | `/api/v1/admin/*` | Admin management APIs |
| Various | `/api/v1/clients/*` | OAuth2 client management |
| GET, POST | `/api/v1/passkey/*` | WebAuthn/Passkey registration and auth |
| GET, POST | `/api/v1/auth/social/*` | Social login callbacks |
| GET, POST | `/api/v1/auth/verify/*` | Email/phone verification |
| GET | `/metrics` | Prometheus metrics |
| GET | `/swagger/*` | Swagger UI (debug mode only) |

## Versioning Policy

gosso uses [Semantic Versioning 2.0.0](https://semver.org/):

- **Major** (`X.0.0`): Breaking changes to Stable APIs. Includes removal of
  endpoints, incompatible schema changes, or new required parameters.
- **Minor** (`X.Y.0`): New features, new endpoints, non-breaking changes to
  Stable APIs. Experimental APIs may change.
- **Patch** (`X.Y.Z`): Bug fixes only. No API changes.

## Deprecation Process

1. **Announcement**: Deprecated endpoints are noted in the CHANGELOG and release
   notes.
2. **Sunset header**: Deprecated endpoints include a `Sunset` HTTP header with
   the removal date ([RFC 8594](https://datatracker.ietf.org/doc/html/rfc8594)).
3. **Grace period**: Deprecated endpoints remain functional for at least
   **6 months** after the deprecation announcement.
4. **Removal**: After the grace period, the endpoint may be removed in the next
   major version.

## Error Format Stability

All Stable APIs return errors in one of two formats:

**Standard JSON error** (auth and admin endpoints):
```json
{
  "code": 401,
  "message": "unauthorized"
}
```

**OAuth2 protocol error** (OAuth2 and OIDC endpoints):
```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired."
}
```

Both formats are Stable within the same major version. Field names and nesting
will not change.
