# GOSSO - AI Agent Architectural & Operational Guidelines

This document defines the **immutable architectural rules, security baselines, and deployment conventions** for AI agents working in this repository. Agents must uphold these principles across all future changes.

---

## 1. Security & Protocol Baseline

1. **OAuth 2.0 & OpenID Connect Standards**:
   - Authorization Code Flow with PKCE (RFC 7636) is mandatory for public and confidential clients.
   - Resource Indicators (RFC 8707) are strictly validated against client `allowed_resources`.
   - Issuer Identification (RFC 9207) `iss` parameter is always included in authorization responses.
   - Token Revocation (RFC 7009) supports RFC compliant token revocation.
   - OIDC RP-Initiated Logout 1.0: Verified clients with registered `post_logout_redirect_uri` are directly 302-redirected with session termination; unregistered requests display a branded confirmation card with CSRF protection.
   - Back-Channel Logout 1.0 delivers asynchronous logout tokens with event claims.

2. **Session & Cookie Security**:
   - All session and auth cookies must use `__Host-` prefix in production (`Path=/; Secure; HttpOnly; SameSite=Lax`).
   - CSRF tokens are cryptographically generated, bound to sessions, and validated on state-changing requests.

---

## 2. Container & Image Conventions

1. **Development Compose (`docker-compose.yml`, `docker-compose.development.yml`)**:
   - Dynamic tag defaults: `${GOSSO_IMAGE:-ghcr.io/rushairer/gosso:main}` to always follow the latest mainline build during development.
   - Never hardcode fixed SHA256 digests in development compose files.
2. **Production Compose (`docker-compose.production.yml`)**:
   - Explicit parameterization: `${GOSSO_IMAGE:?error}` requiring immutable release tags (`:v1.x.y`) or audited digests during deployment.

---

## 3. Dependency & Release Chain

- **Upstream/Downstream Topology**:
  `gosso-client` -> `gosso` -> `gosso-admin` -> `gouno-blog`
- **Release Guidelines**:
  - Follow Semantic Versioning (SemVer).
  - Code changes must pass `gofmt`, linter, and coverage threshold (`COVERAGE_MIN=70%`).
  - Update `CHANGELOG.md` for every release version tag.
