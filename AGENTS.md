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

---

## 4. Capability Module Architecture

- Gosso is a complex application and uses **Capability Module** organization: capability/module first, implementation layer second.
- Business ownership lives under `internal/<capability>/`. A capability may contain `domain`, `repository`, `service`, `controller`, `module.go`, or other internal pieces only when they are actually required. Do not create empty layers for symmetry.
- `domain`, `repository`, `service`, and `controller` are responsibilities inside a capability; they are not global top-level ownership buckets for new business code.
- `module.go` is an optional composition root for capabilities that require dependency-injection aggregation. It is not mandatory for every module.
- Cross-capability dependencies must follow `doc/ARCHITECTURE_INVARIANTS.md`: use narrow interfaces, keep sentinel ownership canonical, and resolve cycles through interface extraction rather than new late-binding patterns.
- Shared adapter utilities such as `internal/controllerutil` may exist when they are genuinely cross-capability infrastructure. Do not move business behavior into generic utility packages merely to avoid explicit module boundaries.
- Gouno Core does not own Gosso's architecture. Gosso currently intentionally provides **no** `.gouno/codegen.yaml`; therefore its project CLI must not expose a `gen` command. This is a valid Gouno v1.3 state, not a missing feature.
- The CLI must use Gouno's dynamic `AttachProjectCommand` integration so a future project-owned Codegen manifest can be introduced without restoring the legacy Core-owned generator catalog.
- Do not add a Gosso `module` generator until at least one reusable generation shape is proven across real Gosso capabilities. In particular, do not assume every module needs all four layers or a `module.go`.
- If project-owned Codegen is introduced later, update the manifest, templates, architecture docs, tests, and CI verification together; never silently redefine upstream/default `suite` semantics.

The detailed layer, dependency, error, transaction, testing, logging, and security invariants remain authoritative in `doc/ARCHITECTURE_INVARIANTS.md`.
