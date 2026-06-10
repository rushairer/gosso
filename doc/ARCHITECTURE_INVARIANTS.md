# Architecture Invariants

This document defines the **non-negotiable rules** for the gosso codebase. Every code review must check changes against these invariants. CI will enforce a subset automatically; the rest are enforced through review.

Each invariant has an **ID** (e.g., `E1`) for easy reference in PR comments and commit messages.

> 本文档定义了 gosso 代码库中**不可违反的规则**。每次代码审查都必须对照检查。CI 会自动检查部分规则，其余通过 review 人工执行。每条规则有唯一 ID（如 `E1`），可在 PR 评论和 commit message 中引用。

---

## Table of Contents

- [E — Error Handling](#e--error-handling)
- [R — Repository Layer](#r--repository-layer)
- [S — Service Layer](#s--service-layer)
- [C — Controller Layer](#c--controller-layer)
- [D — Dependency Injection](#d--dependency-injection)
- [T — Testing](#t--testing)
- [L — Logging](#l--logging)
- [X — Cross-Cutting Concerns](#x--cross-cutting-concerns)

---

## E — Error Handling

### E1: Sentinel errors are defined once per concept

Sentinel errors for the same business concept must be defined in **exactly one** package. Other packages import and reference that single definition.

| Concept | Canonical Location | Prohibited Duplicates |
|---------|-------------------|----------------------|
| `ErrAccountNotActive` | `internal/account/service/errors.go` | `internal/auth/service/errors.go` |
| `ErrAccountNotFound` | `internal/account/repository/account_repository.go` | `internal/auth/service/errors.go` |

**How to check**: `grep -rn 'errors.New(' internal/ | grep -v _test.go` — the same error message string must not appear in two different packages.

### E2: Cross-package error wrapping uses `%w`

When a service calls a repository and wants to return a different error to the caller, it must either:
- Return the repository's sentinel directly, or
- Wrap it with `fmt.Errorf("context: %w", repoErr)`

Never re-create the same error with `errors.New()` — this breaks `errors.Is()` chains.

### E3: No inline `errors.New()` in controllers

Controller files (`internal/*/controller/*.go`) must not contain `errors.New(...)` calls. All error responses must come from:
- Sentinel errors defined in service/domain packages, mapped via `handleServiceError`
- `gouno.NewErrorResponse()` with appropriate status codes

**Exception**: `400 Bad Request` for JSON parsing failures is acceptable inline.

### E4: Controller error mapping is centralized

Each controller must use a shared `handleServiceError(ctx, err, errorMap)` helper (or equivalent) instead of hand-written `if errors.Is(err, X) { ... } else if ...` chains. The error map defines `sentinel error → HTTP status code + message` for each possible service error.

```go
// CORRECT: error map
var accountErrorMap = map[error]struct {
    status  int
    message string
}{
    accountService.ErrAccountNotFound:    {404, "account not found"},
    accountService.ErrAccountNotActive:   {409, "account is not active"},
    accountService.ErrUsernameAlreadyTaken: {409, "username already taken"},
}

// INCORRECT: hand-written chain
if errors.Is(err, accountService.ErrAccountNotFound) {
    ctx.JSON(404, ...)
} else if errors.Is(err, accountService.ErrAccountNotActive) {
    ctx.JSON(409, ...)
}
```

### E5: New sentinel errors go in the correct file

- Business rule violations → `internal/<module>/service/errors.go`
- Data access failures → `internal/<module>/repository/<entity>_repository.go`
- Domain validation → `internal/<module>/domain/` (if applicable)

Never define sentinels in controller files.

---

## R — Repository Layer

### R1: Scan logic is extracted into helpers

Every entity that is scanned from SQL rows must have a private `scanXxx` helper. All query methods (`FindByID`, `FindByUsername`, `FindAll`, etc.) call this helper instead of duplicating the `Scan` + `json.Unmarshal` block.

```go
// CORRECT: shared helper
func scanAccount(scanner interface{ Scan(...any) error }) (*domain.Account, error) {
    var a domain.Account
    var metadataJSON []byte
    err := scanner.Scan(&a.ID, &a.Username, ..., &metadataJSON)
    if err != nil {
        return nil, err
    }
    // unmarshal metadata...
    return &a, nil
}

// INCORRECT: each method re-implements scanning
func (r *accountRepo) FindByID(...) {
    row := r.db.QueryRowContext(ctx, query, id)
    var a domain.Account
    var metadataJSON []byte
    err := row.Scan(&a.ID, &a.Username, ..., &metadataJSON)
    // ... 20 more lines duplicated in every method
}
```

### R2: Dynamic SQL uses whitelists

Dynamic WHERE clauses must validate column names against a hardcoded whitelist before interpolation. Direct string concatenation of user input into SQL is forbidden.

```go
// CORRECT: whitelist validation
var validStatuses = map[string]bool{"active": true, "suspended": true, "deleted": true}
if !validStatuses[status] {
    return nil, 0, fmt.Errorf("invalid status: %s", status)
}
where := fmt.Sprintf("status = '%s'", status) // safe: validated against whitelist

// INCORRECT: no validation
where := fmt.Sprintf("status = '%s'", userInput) // SQL injection risk
```

### R3: Repositories do not manage transactions

Repository methods accept `*sql.Tx` as a parameter but never create, commit, or rollback transactions. Transaction lifecycle is the responsibility of the service layer.

```go
// CORRECT: service manages tx
func (s *accountService) DeleteAccount(ctx context.Context, id string) error {
    tx, _ := s.db.BeginTx(ctx, nil)
    defer tx.Rollback()
    s.repo.SoftDeleteAccount(ctx, tx, id, time.Now())
    // ...
    return tx.Commit()
}

// INCORRECT: repo manages tx
func (r *accountRepo) DeleteAccount(ctx context.Context, id string) error {
    tx, _ := r.db.BeginTx(ctx, nil)  // WRONG: repo should not own tx
    // ...
}
```

---

## S — Service Layer

### S1: Cross-module dependencies use interfaces

When module A depends on module B, module A defines a narrow interface for the capability it needs. Module B's service implements that interface implicitly (Go duck typing). Direct import of concrete types across module boundaries is forbidden.

```go
// CORRECT: account module defines its own interface
type SessionRevoker interface {
    RevokeAllForAccount(ctx context.Context, accountID string) error
}

// INCORRECT: account module imports concrete session service
import "github.com/rushairer/gosso/internal/session/service"
func (s *accountService) Delete(...) {
    s.sessionSvc.(*service.SessionServiceImpl).RevokeAll(...) // WRONG
}
```

### S2: Configuration flows through constructor or config struct

Service configuration (timeouts, limits, defaults) must be passed through the constructor or a config struct. Setter methods (`SetLoginRateLimitWindow`, `SetSessionTTL`, etc.) are a legacy pattern — new code should not introduce new setters.

```go
// CORRECT: config struct
type AuthConfig struct {
    LoginRateLimitWindow  time.Duration
    LoginMaxAttempts      int
    LoginMaxAttemptsPerIP int
}

func NewAuthService(repo AccountRepository, cfg AuthConfig) AuthService { ... }

// INCORRECT: new setter methods
func (s *authService) SetNewFeatureTimeout(d time.Duration) { s.timeout = d }
```

---

## C — Controller Layer

### C1: Every new endpoint has rate limiting

Every new route registered in `router/*.go` must have a corresponding rate limit configuration. The rate limit bucket name must be documented in the route registration.

```go
// CORRECT: rate limit declared alongside route
router.POST("/api/auth/login", rateLimiter.Limit("auth:login"), authController.Login)

// INCORRECT: no rate limit
router.POST("/api/auth/login", authController.Login)
```

### C2: Error response format follows conventions

| Endpoint Category | Error Format | Example |
|------------------|--------------|---------|
| OAuth2 (RFC 6749) | `{"error": "...", "error_description": "..."}` | Token, Introspect, Authorize |
| OIDC (OpenID Connect) | OAuth2 format for auth errors | UserInfo, Logout |
| Admin / Auth / General | `gouno.NewErrorResponse(status, message)` | Accounts, Sessions, Clients |

Do not mix formats within the same endpoint.

### C3: Security-sensitive errors are opaque to clients

Endpoints handling authentication, MFA, password reset, or account verification must return generic error messages to prevent information leakage:

```go
// CORRECT: opaque error
ctx.JSON(401, gouno.NewErrorResponse(401, "invalid credentials"))

// INCORRECT: leaks account existence
ctx.JSON(401, gouno.NewErrorResponse(401, "account not found"))
ctx.JSON(401, gouno.NewErrorResponse(401, "account is locked"))
```

**Exception**: Admin endpoints may return specific errors since they require authentication and authorization.

---

## D — Dependency Injection

### D1: No new late-bind patterns

The existing `BindSessionRevoker` / `BindOAuth2ClientDeleter` late-bind pattern is a legacy workaround for circular dependencies. New modules must resolve circular dependencies through interface extraction, not late binding.

If you find yourself writing a `BindXxx` function:
1. First, check if the circular dependency can be broken by extracting a narrow interface
2. If not, raise the issue in the PR — do not silently introduce a new late-bind

### D2: Module initialization has test coverage

Every `InitializeXxxModule` function in `internal/*/module.go` must have at least a smoke test that verifies:
- All dependencies are properly wired
- No nil panics on first method call
- Late-bind functions (if any) complete successfully

---

## T — Testing

### T1: New public functions have tests

Every new exported function or method must have at least one test. This is enforced by the existing 50% overall coverage threshold, but reviewers should check at the function level.

**Exception**: Thin wrapper functions that delegate directly (e.g., `func (s *svc) Foo(ctx context.Context) error { return s.inner.Foo(ctx) }`).

### T2: Bug fixes include regression tests

A PR that fixes a bug **must** include a test that:
1. Fails before the fix
2. Passes after the fix
3. Describes the scenario in the test name

```go
// CORRECT: regression test with scenario description
func TestLogin_RateLimitNotBypassedByIPv6Variants(t *testing.T) {
    // Regression: IPv6 address variants (e.g., ::1 vs 0:0:0:0:0:0:0:1)
    // were counted as separate rate limit keys
}

// INCORRECT: generic test name
func TestLogin(t *testing.T) {
    // What scenario does this test?
}
```

### T3: Module-level coverage awareness

The CI reports per-module coverage. While the overall 50% threshold is the hard gate, per-module coverage below 40% triggers a warning in the PR. Contributors should aim to increase (not decrease) module coverage with each PR.

---

## L — Logging

### L1: Structured logging with `*zap.Logger`

Service and repository layers must use `*zap.Logger` (not `*zap.SugaredLogger`). Controller layers obtain a logger through a shared helper.

```go
// CORRECT: structured logger
s.logger.Info("session created",
    zap.String("account_id", accountID),
    zap.String("session_id", sessionID),
)

// INCORRECT: sugar logger
s.logger.Infof("session created for account %s", accountID)
```

### L2: No sensitive data in logs

The following must never appear in log output:
- Passwords, password hashes
- Tokens (access, refresh, ID tokens)
- Session IDs
- TOTP secrets and codes
- OAuth2 authorization codes
- CSRF tokens

Use the utility masking functions in `internal/utility/mask.go` when logging identifiers that partially overlap with sensitive data.

---

## X — Cross-Cutting Concerns

### X1: Redis unavailability is handled explicitly

Every Redis operation must handle the case where Redis is unavailable. The behavior (fail-open vs fail-closed) must be **configurable and documented**, not silently ignored.

```go
// CORRECT: explicit handling
if err := s.redis.Set(ctx, key, val, ttl).Err(); err != nil {
    if s.failOpen {
        s.logger.Warn("redis unavailable, continuing without rate limit", zap.Error(err))
        return nil // fail-open: allow the request
    }
    return fmt.Errorf("rate limiter unavailable: %w", err) // fail-closed: reject
}

// INCORRECT: silent ignore
s.redis.Set(ctx, key, val, ttl).Err() // error discarded

// INCORRECT: always fail-open without config
if err := s.redis.Set(ctx, key, val, ttl).Err(); err != nil {
    return nil // always fail-open: should be configurable
}
```

### X2: Token lifecycle operations have audit logs

Every operation that creates, refreshes, rotates, or revokes a token must emit an audit log entry. This includes:
- Access token creation
- Refresh token rotation
- Token revocation (individual and bulk)
- Session termination
- Password change (which should revoke all tokens)

---

## Enforcement Levels

| Level | Description | How |
|-------|-------------|-----|
| **CI-block** | PR cannot merge if violated | golangci-lint + architecture-check CI job |
| **CI-warn** | Warning in PR, does not block merge | Coverage report per module |
| **Review** | Enforced by human reviewer | All other invariants |

### Currently Enforced by CI (automated)

| Invariant | Mechanism |
|-----------|-----------|
| E3 | `script/check-architecture.sh` — no `errors.New` in controllers |
| L1 | `script/check-architecture.sh` — no `.Sugar()` in service/repo |
| R2 | golangci-lint `gosec` (if enabled) |
| T3 | Per-module coverage report |
| General | golangci-lint: `errcheck`, `govet`, `staticcheck`, `wrapcheck`, `errorlint`, `dupl` |

### Currently Enforced by Review (manual)

All other invariants. As the project matures, more invariants should be promoted to CI enforcement.

---

## References

- [ADR-001: Sentinel Error Strategy](ADR/0001-sentinel-error-strategy.md)
- [ADR-002: Repository Scan Helper Pattern](ADR/0002-repository-scan-helper.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [CHANGELOG.md](../CHANGELOG.md)

---

# 架构不变量

本文档定义了 gosso 代码库中**不可违反的规则**。每次代码审查都必须对照检查。CI 会自动检查部分规则，其余通过 review 人工执行。每条规则有唯一 ID（如 `E1`），可在 PR 评论和 commit message 中引用。

## 执行级别

| 级别 | 描述 | 方式 |
|------|------|------|
| **CI 阻断** | 违反则 PR 无法合并 | golangci-lint + architecture-check CI job |
| **CI 警告** | PR 中显示警告，不阻断合并 | 模块级覆盖率报告 |
| **Review** | 由人工 reviewer 执行 | 其余所有不变量 |

详细规则请参考上方英文版。
