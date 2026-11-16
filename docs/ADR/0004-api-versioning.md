# ADR-0004: API Versioning

- **Status**: Accepted
- **Date**: 2026-06-21

## Context

At the time of this 2026-06-21 decision, gosso's management API (`/api/auth/*`, `/api/oauth2/clients`, `/api/admin/*`) used unversioned paths. As the API matures, breaking changes will be inevitable. We need a versioning strategy that:

1. Allows non-breaking evolution without version bumps
2. Supports breaking changes with clear migration paths
3. Doesn't interfere with OAuth2/OIDC protocol endpoints (which follow RFCs)
4. Is simple for API consumers to understand

## Decision

We adopt **URI path versioning** for management endpoints:

- Current version: `/api/v1/`
- Historical unversioned application route families receive HTTP 308 redirects to `/api/v1/*` (see the current [API Versioning Strategy](../API_VERSIONING.md)); unknown paths and later explicit versions never downgrade to v1.

### What gets versioned

| Endpoint | Versioned? | Reason |
|----------|-----------|--------|
| `/api/auth/*` | ✅ `/api/v1/auth/*` | Application-specific, may change |
| `/api/oauth2/clients` | ✅ `/api/v1/oauth2/clients` | Admin CRUD, may change |
| `/api/admin/*` | ✅ `/api/v1/admin/*` | Admin API, may change |
| `/oauth2/*` | ❌ | Follows RFC 6749 |
| `/.well-known/*` | ❌ | Follows RFC 8414 |
| `/oidc/*` | ❌ | Follows OpenID Connect Core 1.0 |
| `/health`, `/readiness` | ❌ | Infrastructure |

### Alternatives considered

- **Header versioning** (`Accept: application/vnd.gosso.v1+json`): More RESTful but harder to test with curl/browser, less discoverable
- **Query parameter** (`?version=1`): Easy but pollutes caching, not standard
- **No versioning**: Acceptable for now but blocks future breaking changes

## Consequences

- **Positive**: Clear, explicit, easy to grep and route
- **Positive**: Compatible with OpenAPI spec and Swagger UI
- **Positive**: 308 redirects maintain backward compatibility during migration
- **Negative**: URL changes require client updates (mitigated by redirects)
- **Negative**: Longer URLs (mitigated by being a management API, not a high-volume endpoint)

## Implementation clarification (2026-11-16)

The original group-scoped redirect middleware did not handle requests for unregistered legacy paths. Compatibility now runs in the global Gin chain before CSRF, limited to known unversioned application route families. Canonical endpoints still enforce authentication, CSRF, authorization and rate limiting. The current operational behavior is documented in [English](../API_VERSIONING.md) and [简体中文](../API_VERSIONING.zh-CN.md). This ADR preserves the original decision history instead of overwriting it.
