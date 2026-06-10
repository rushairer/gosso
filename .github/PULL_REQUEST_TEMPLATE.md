## What does this PR do?

<!-- A brief description of the change and its motivation. -->

## Related issues

<!-- Link related issues: Fixes #123, Closes #456 -->

## Checklist — Code Quality (required)

- [ ] `go mod tidy` — no stray dependencies
- [ ] `make lint` passes
- [ ] `make test` passes
- [ ] `make build` succeeds
- [ ] New/changed behavior is covered by tests
- [ ] Bug fixes include a regression test that fails before the fix

## Checklist — Architecture Invariants (required)

<!-- Reference: doc/ARCHITECTURE_INVARIANTS.md -->
<!-- Check all that apply; leave unchecked items that are not relevant to this PR -->

**Error handling (E)**
- [ ] New sentinel errors are defined in the canonical package (not in controllers)
- [ ] No inline `errors.New()` in controller files (use sentinels from service/domain)
- [ ] Cross-package errors are wrapped with `%w`
- [ ] Controller error mapping uses `handleServiceError` helper

**Repository layer (R)**
- [ ] Scan logic is extracted into `scanXxx` helper (no duplicated Scan blocks)
- [ ] Dynamic SQL uses whitelist validation
- [ ] Repository does not manage transactions (no `BeginTx` in repo files)

**Service layer (S)**
- [ ] Cross-module dependencies use interfaces (not concrete types)
- [ ] Configuration flows through constructor or config struct (not new setters)

**Controller layer (C)**
- [ ] New endpoints have rate limiting configured
- [ ] Error response format follows conventions (RFC format for OAuth2/OIDC, `gouno.NewErrorResponse` for others)
- [ ] Security-sensitive errors are opaque to clients

**Logging (L)**
- [ ] Service/repository layers use `*zap.Logger` (not Sugar)
- [ ] No sensitive data in log output (tokens, passwords, session IDs, TOTP codes)

**Cross-cutting (X)**
- [ ] Redis unavailability is handled explicitly (fail-open/fail-closed configurable)
- [ ] Token lifecycle operations have audit logs

## Checklist — Security (if applicable)

- [ ] No secrets, tokens, or passwords in the diff
- [ ] `redirect_uri` validated with exact match (if changed)
- [ ] `state` / `nonce` parameters validated (if OAuth/OIDC flow changed)
- [ ] JWT verification checks `iss`, `aud`, `exp`, `alg` (if token handling changed)
- [ ] Audit log covers new auth events (if applicable)
- [ ] Sensitive data is not logged

## Review Scope

<!-- Mark the dimensions reviewers should focus on. This helps distribute attention and prevents "everything at once" review fatigue. -->

- [ ] RFC compliance (OAuth2 / OIDC / WebAuthn)
- [ ] Security boundaries (info leakage, race conditions, rate limit bypass)
- [ ] Error handling completeness
- [ ] Code duplication / interface design
- [ ] Test coverage adequacy

## Additional notes

<!-- Anything reviewers should watch out for: migration steps, breaking changes, known limitations. -->
