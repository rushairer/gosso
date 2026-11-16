# API Versioning Strategy

[简体中文](API_VERSIONING.zh-CN.md)

## API contract boundaries

The application API path version is independent of the server release version. Gosso v1.7.x still serves application API v1; /api/v2/ must only be introduced deliberately for incompatible contract changes.

| Surface | Canonical prefix | Policy |
|---|---|---|
| Authentication and MFA | /api/v1/auth/* | Versioned application API |
| Passkeys | /api/v1/passkey/*, /api/v1/passkeys | Versioned application API |
| OAuth client management | /api/v1/oauth2/clients | Versioned application API |
| Administration | /api/v1/admin/* | Versioned application API |
| OAuth2 / OIDC | /oauth2/*, /oidc/*, /.well-known/* | Standard protocol and discovery routes; not application-versioned |
| Infrastructure | /health, /readiness, /metrics | Not application-versioned |

Protocol endpoints evolve according to implemented specifications and interoperability constraints, not automatically with application API versions or server SemVer.

## Legacy unversioned route compatibility

The following historical API route families return HTTP 308 Permanent Redirect to their /api/v1 equivalents: /api/auth/*, /api/admin/*, /api/passkey/*, /api/passkeys and /api/passkeys/*, /api/oauth2/clients and /api/oauth2/clients/*. The redirect preserves the HTTP method and raw query string. It runs before CSRF, while the canonical destination continues to enforce CSRF, authentication, authorization and rate limiting. The redirect does not execute an operation.

Unknown /api/* paths, future /api/v2/* paths and protocol paths are not redirected. API consumers should use canonical URLs directly; request bodies or Authorization headers may not be forwarded consistently by every client across redirects.

## Evolution and deprecation

- Non-breaking additions can extend application API v1.
- Incompatible contracts require a deliberate new prefix (such as /api/v2/) and migration guidance; do not automatically redirect v1 to v2.
- Deprecating a supported API version requires a published announcement, a minimum six-month migration window, and applicable Sunset headers. An expired endpoint may return 410 Gone only after it is explicitly implemented and released.
- The historical *unversioned* redirects are transitional compatibility. No removal date has been announced.

## Sources of truth

- [ADR-0004](ADR/0004-api-versioning.md) records the original architecture decision.
- router/web.go registers the canonical API; middleware/api_version_redirect.go handles legacy redirects before CSRF.
- docs/openapi.yaml documents the canonical contracts; [API Stability](api-stability.md) defines support tiers.

Current application API path version: **v1**.
