# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **Security**: Remove hardcoded passwords and secrets from `.env.*` files and `config/development.yaml`; use environment variable references instead.
- **Security**: Atomic refresh token rotation via Redis Lua script — eliminates TOCTOU race condition between GET and DELETE (`internal/token/service/token_service.go`).
- **Security**: MFAService transaction error propagation — `deleteUnverifiedTOTP`, `deleteBackupCodes`, and `VerifyBackupCode` now properly return errors instead of silently discarding them (`internal/auth/service/mfa_service.go`).
- **Security**: Password reset token is now deleted only after successful password update, not before — prevents token loss on DB failure (`internal/auth/service/password_reset_service.go`).
- **Security**: Social login now enforces session limits by reusing the same `CreateSessionAndTokens` path as password login (`internal/auth/service/social_login_service.go`).
- **Security**: OAuth state cookie uses dynamic `Secure` flag based on `!cfg.WebServerConfig.Debug` instead of hardcoded `false` (`internal/auth/controller/auth_controller.go`).
- **Security**: JWT middleware only reads token from `Authorization: Bearer` header — removes fallback to query/form params (`internal/auth/middleware/auth_middleware.go`).
- **Security**: ID Token `jti` claim uses unique UUID per token instead of reusing `accountID` (`internal/oidc/service/id_token_service.go`).
- **Security**: ID Token email lookup fixed — uses `FindByAccountAndType(accountID)` instead of `FindByTypeAndIdentifier("")` (`internal/oidc/service/id_token_service.go`).
- Replace `logger.Fatal` with `logger.Error` for graceful shutdown in web server (`cmd/gouno/web.go`).

### Changed

- Add standalone `RunInTransaction(*sql.DB)` helper; replace 24 manual `BeginTx/defer Rollback/Commit` patterns across 6 service files (`internal/db/transaction.go`).
- Extract inline magic numbers into named constants: `loginRateLimitWindow`, `loginMaxAttempts`, `MinPasswordLength`, `PasswordResetRevokeTimeout` (`internal/auth/service/auth_login.go`, `password_reset_service.go`, `account_service.go`).
- `AccountModule` now exports shared repositories; auth, OIDC, and OAuth2 modules reuse them instead of creating duplicate instances (`internal/account/wire.go`, `internal/auth/wire.go`, `internal/oidc/wire.go`, `internal/oauth2/wire.go`).
- `OAuthState` uses `crypto/rand` for state parameter generation instead of UUID (`internal/auth/controller/auth_controller.go`).
- `SocialLoginService` depends on `SessionTokenCreator` interface instead of duplicating session/token creation logic (`internal/auth/service/interfaces.go`, `social_login_service.go`).
- Email service reuses a single `gomail.Dialer` instance instead of creating one per send (`internal/notification/service/email_service.go`).
- PII masking in verification service logs (`internal/auth/service/verification_service.go`).

- Add `AuthModule` struct to `internal/auth/wire.go` — replaces 7-value tuple return from `InitializeAuthModule`.
- Add `gomail.v2` dependency for email sending with STARTTLS support.
- Add `cryptoRandInt` helper to `internal/captcha/service/captcha_service.go` for cryptographically secure random number generation.

### Changed

- **Security**: Verification code comparison now uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks (`internal/auth/service/verification_service.go`).
- **Security**: Captcha generation now uses `crypto/rand` instead of `math/rand` for unpredictable codes (`internal/captcha/service/captcha_service.go`).
- **Security**: `config.Validate()` now checks that `JWTSecret` is non-empty (`config/config.go`).
- Email service now uses `gomail.v2` library instead of `net/smtp` for reliable STARTTLS support (`internal/notification/service/email_service.go`).
- `InitializeAuthModule` returns `*AuthModule` struct instead of 7-value tuple (`internal/auth/wire.go`).
- `StubSMSService` now accepts a logger and returns a more user-friendly error message (`internal/notification/service/sms_service.go`).
- `AuthService` split into three files: `auth_service.go` (core), `auth_login.go` (login/logout), `auth_session.go` (session/refresh).
- Redis error handling in verification and password reset services now includes comments documenting fail-open strategy.

### Fixed

- Remove dead code: redundant `os.Exit(1)` after `log.Fatalf` in `cmd/gouno/root.go`.

### Removed

- Remove unused `Group` struct and related methods from `internal/account/domain/role.go`.
- Remove `buildMessage` method from `EmailService` (replaced by gomail).
- Remove `buildMessage` tests from `internal/notification/service/notification_service_test.go`.

### Added

- Add sentinel errors `ErrAccountNotFound`, `ErrCredentialNotFound`, `ErrRoleNotFound`, `ErrFederatedIdentityNotFound` to repository layer for `errors.Is()` matching.
- Add `AuthURL`, `TokenURL`, `UserInfoURL` fields to `OAuthProviderConfig` — OAuth2 provider URLs are now configurable via YAML with sensible defaults.
- Add `rate_limits` section to `config/production.yaml` for per-endpoint rate limit configuration.
- Add `cors` section to `config/production.yaml` with GOUNO_ environment variable placeholders.
- Add `Validate()` check: rate limits values must be non-negative.
- Add unit tests for middleware: RequestIDMiddleware, ZapLoggerMiddleware, CSRFMiddleware, generateCSRFToken (`middleware/middleware_test.go`).
- Add OAuth2 Device Authorization Grant (RFC 8628) — enables input-constrained devices (CLIs, smart TVs, IoT) to obtain tokens.
- Add `POST /oauth2/device/code` endpoint — initiates device authorization flow, returns `device_code`, `user_code`, `verification_uri`.
- Add `GET/POST /oauth2/device` — user-facing HTML page for entering and approving device codes.
- Add `urn:ietf:params:oauth:grant-type:device_code` grant type to token endpoint with poll rate limiting (`slow_down`), expiry, and status checks.
- Add `DeviceCodeService` (`internal/oauth2/service/device_code_service.go`) — Redis-backed storage with crypto/rand code generation, user code format `XXXX-XXXX`.
- Add `DeviceCode` domain model (`internal/oauth2/domain/device_code.go`) — status lifecycle (pending/authorized/denied/used).
- Add `DeviceCodeManager` interface to `OAuth2Controller` for testability.
- Add `DeviceCodeExpiry` and `DeviceCodeInterval` to `AuthConfig`.
- Add `device_authorization_endpoint` and `urn:ietf:params:oauth:grant-type:device_code` grant type to OIDC discovery document.
- Add unit tests for device code domain, controller endpoints (10 tests), and discovery document.
- Add unit tests for audit domain: NewRecord, action constants, UUID generation (`internal/audit/domain/audit_test.go`).
- Add unit tests for audit context: SetMetadata, IPFromContext, UserAgentFromContext, RequestIDFromContext (`internal/audit/context_test.go`).
- Add unit tests for DB transaction helpers: WithTransaction, WithTransactionIsolation, panic recovery (`internal/db/transaction_test.go`).
- Add `AuthConfig` to configuration (JWT secret, issuer, token expiry, scopes).
- Add `golang-jwt/jwt/v5` dependency for JWT token signing and verification.
- Add `internal/token/domain/token.go` — AccessTokenClaims and RefreshToken value objects.
- Add `internal/token/service/token_service.go` — JWT lifecycle (sign, verify, refresh token rotation).
- Add `internal/oauth2/` module — OAuth2 Authorization Server (client, authorization code, consent).
- Add `internal/auth/` module — Login orchestration (username/password, logout, refresh tokens).
- Add `internal/oidc/` module — OpenID Connect Provider (ID token, discovery, JWKS, userinfo).
- Add JWT authentication middleware (`internal/auth/middleware/auth_middleware.go`).
- Add HTTP controllers for auth, OAuth2 protocol, client management, and OIDC endpoints.
- Add database migration `0003_oauth2` — `oauth2_clients` table.
- Wire all modules into web server startup (`cmd/gouno/web.go`).
- Add unit tests for token, OAuth2 (auth code, consent, client), and OIDC (ID token) services.
- Add `HashPKCEVerifier` helper to `internal/oauth2/domain/authorization_code.go`.
- Add refresh token-session index (`session_tokens:<id>` Redis SET) for `RevokeAllForSession`.
- Add `client_credentials` grant type to OAuth2 token endpoint (RFC 6749 §4.4).
- Add HTML consent page for OAuth2 authorization flow (`internal/oauth2/controller/template/consent.html`).
- Add TOTP-based MFA (`internal/auth/service/mfa_service.go`) — enrollment, verification, activation, backup codes.
- Add MFA endpoints: `POST /api/auth/mfa/verify`, `enroll`, `activate`, `DELETE /api/auth/mfa`, `POST /api/auth/mfa/backup-codes`.
- Add login failure rate limiting (5 attempts / 15 min per username, Redis-backed).
- Add token introspection endpoint `POST /oauth2/introspect` (RFC 7662).
- Add CORS configuration (`CORSConfig` in config) with `gin-contrib/cors` middleware.
- Add social login service (`internal/auth/service/social_login_service.go`) — Google, GitHub, WeChat OAuth2 callback handling.
- Add social login endpoints: `GET /api/auth/social/:provider`, `GET /api/auth/social/:provider/callback`.
- Add `OAuthProvidersConfig` to configuration for social login provider credentials.
- Add `pquerna/otp` and `gin-contrib/cors` dependencies.
- Add `internal/token/service/key_service.go` — RSA key pair management (generate, load from PEM, auto-create, key ID fingerprint).
- Add `PrivateKeyPath` and `KeyID` fields to `AuthConfig` for RS256 key configuration.
- Add `internal/notification/service/email_service.go` — SMTP email sending for verification codes.
- Add `internal/notification/service/sms_service.go` — SMS service interface with stub implementation.
- Add `internal/auth/service/verification_service.go` — Verification code generation, storage (Redis), cooldown, and validation.
- Add `POST /api/auth/verify/send` — Send verification code (email or phone).
- Add `POST /api/auth/verify/confirm` — Confirm verification code and mark credential as verified.
- Add `internal/auth/service/password_reset_service.go` — Password reset flow (request, token generation, verify, password update).
- Add `POST /api/auth/password/forgot` — Request password reset email (unauthenticated, anti-enumeration).
- Add `POST /api/auth/password/reset` — Reset password with token (unauthenticated).
- Add `PasswordResetEmailSender` interface and `SendPasswordResetLink` method to `EmailService`.
- Add `RevokeAllForAccount` to `SessionService` — revoke all sessions for an account via Redis Set index (`account_sessions:<accountID>`).
- Add `PasswordResetBaseURL` to `AuthConfig` for reset link generation.
- Add `AdminRequiredMiddleware` to `internal/auth/middleware/` — role-based admin access control.
- Add `internal/admin/controller/admin_controller.go` — Admin endpoints for account management.
- Add `GET /api/admin/accounts` — Paginated account list with status filter.
- Add `GET /api/admin/accounts/:account_id` — Account detail.
- Add `POST /api/admin/accounts/:account_id/disable` — Suspend account.
- Add `POST /api/admin/accounts/:account_id/enable` — Activate account.
- Add `DELETE /api/admin/accounts/:account_id` — Soft delete account.
- Add `GET /api/admin/accounts/:account_id/roles` — List account roles.
- Add `POST /api/admin/accounts/:account_id/roles` — Assign role to account.
- Add `DELETE /api/admin/accounts/:account_id/roles/:role_id` — Remove role from account.
- Add `FindAll` to `AccountRepository` — paginated account query with status filter.
- Add `ListAccounts`, `SuspendAccount`, `ActivateAccount`, `GetAccountRoles` to `AccountService`.
- Add `internal/audit/domain/actions.go` — audit action constants for auth, account, role, and MFA events.
- Add `internal/audit/domain/record_builder.go` — `NewRecord` factory for `AuditRecord`.
- Add `internal/audit/context.go` — context utilities for passing IP/user-agent through service layers.
- Add `AuditMetadataMiddleware` to `internal/auth/middleware/` — extracts client IP/user-agent into request context.
- Add `Auditor.Log` method for direct audit record submission (nil-receiver safe).
- Add database migration `0004_audit_dd_column` — adds `dd` date-partition column to `audit_record` table.
- Add audit logging to `AuthService.LoginByUsernamePassword` (success/failure), `VerifyMFALogin` (success/failure), `Logout`.
- Add audit logging to `AccountService.RegisterAccount`, `SoftDeleteAccount`, `ChangePassword`, `SuspendAccount`, `ActivateAccount`, `AssignRole`, `RemoveRole`.
- Add OpenAPI 3.0 specification (`docs/openapi.yaml`) — complete API documentation for all 39 endpoints.
- Add Swagger UI served at `/swagger/index.html` with `go:embed` static assets (`docs/swagger.go`).
- Add WebAuthn/Passkey support (`github.com/go-webauthn/webauthn`).
- Add `webauthn_credentials` table migration (`0005_webauthn_credentials`).
- Add `PasskeyService` — registration, login (discoverable + known-user), MFA, credential management.
- Add passkey endpoints: `POST /api/auth/passkey/register/{begin,complete}`, `POST /api/auth/passkey/login/{begin,complete}`, `GET /api/auth/passkeys`, `DELETE /api/auth/passkeys/:id`, `POST /api/auth/passkey/mfa/{begin,complete}`.
- Add `WebAuthnCredential` domain model and `WebAuthnCredentialRepository`.
- Add `mfa_types` field to login MFA response — lists available MFA methods (`totp`, `passkey`).
- Add `type` field to MFA verify request for passkey MFA flow.
- Add Redis-backed distributed rate limiter (`middleware/redis_ratelimit.go`) — sliding window with Lua script.
- Add per-endpoint rate limiting: login (5/min), MFA (10/min), passkey (10/min), password reset (60/min).
- Add CSRF double-submit cookie middleware (`middleware/csrf.go`) — skips Bearer auth and GET/HEAD/OPTIONS.
- Add `RateLimitsConfig` for per-endpoint rate limit configuration.
- Add session management endpoints: `GET /api/auth/sessions` (list active sessions), `DELETE /api/auth/sessions/:id` (revoke specific session).
- Add `ListSessionsByAccount` and `RevokeSession` to session service.
- Add concurrent session limit (default 10) with automatic oldest-session eviction.
- Add integration test infrastructure (`internal/testutil/testutil.go`) — shared DB/Redis setup, migrations, account seeding.
- Add integration tests for auth service: login success/failure, token refresh, logout, rate limiting, session list/revoke.
- Add integration tests for session service: CRUD, validation, account session listing, revoke, session limit enforcement.
- Add integration tests for Redis rate limiter middleware: within-limit, over-limit, per-key isolation, response headers.
- Add `make test-integration` target for running integration tests against Docker test environment.
- Add multi-stage `Dockerfile` for production builds (Go 1.23 builder + Alpine runtime, ~20MB image).
- Add `.dockerignore` for optimized Docker build context.
- Add `config/nginx.conf` — reverse proxy configuration for production.
- Add `config/redis.conf` — production Redis configuration with persistence and memory limits.
- Add `config/postgresql.conf` — production PostgreSQL configuration.
- Add `script/postgres/init.sh` — database extension initialization script.
- Add GitHub Actions CI pipeline (`.github/workflows/ci.yml`) — lint, unit tests, integration tests, build, Docker image.
- Add OIDC RP-Initiated Logout 1.0 support: `GET/POST /oidc/logout` endpoint with `id_token_hint`, `client_id`, `post_logout_redirect_uri`, and `state` parameters.
- Add `LogoutService` to OIDC module — validates ID token hints (accepts expired tokens per spec), revokes sessions and refresh tokens by account or session.
- Add `end_session_endpoint` to OIDC discovery document (`/.well-known/openid-configuration`).
- Add `post_logout_redirect_uris` column to `oauth2_clients` table (migration `0007`).
- Add `ValidatePostLogoutRedirectURI` method to `OAuth2Client` domain model.
- Add unit tests for `ValidateIDTokenHint`: valid, expired, empty, invalid JWT, wrong issuer, no audience, bad signature, wrong algorithm.
- Add unit tests for OIDC Logout controller: id_token_hint validation, Bearer token fallback, post-logout redirect, client ID mismatch, no session.

### Changed

- `SocialLoginService.createNewUser` now uses repository methods (`accountRepo.CreateAccount`, `credentialRepo.CreateCredentials`, `federatedIdentityRepo.CreateFederatedIdentity`) instead of raw SQL.
- `NewSocialLoginService` now accepts `accountRepo.AccountRepository` parameter.
- `SocialLoginService.GetAuthURL` reads authorization URL from provider config instead of hardcoded switch statement.
- `buildOAuthProviders` in `cmd/gouno/web.go` now reads URLs from config with `defaultIfEmpty` fallback.
- Remove global in-memory rate limiter middleware (problematic in multi-instance deployments); Redis-based per-endpoint rate limiting remains.
- Repository not-found errors standardized to sentinel errors with `fmt.Errorf("%w: %s", ErrXxxNotFound, identifier)` pattern.
- `SessionService.EnforceSessionLimit` now uses `sort.Slice` instead of bubble sort.
- Fix log level comments in all YAML configs: `3: dpanic, 4: panic, 5: fatal`.
- Remove dead code: `db.Connect()`, `db.Config`, `BigCacheConfig` struct and YAML sections.
- Remove unused `db *sql.DB` field from `AuthService`.
- `InitializeAuthModule` now returns `*sessionService.SessionService` as 7th return value.
- `InitializeOIDCModule` now accepts `*sessionService.SessionService` parameter and returns `*oidcService.LogoutService` as 5th value.
- `NewOIDCController` now accepts `logoutSvc`, `clientRepo`, `tokenSvc`, and `issuer` parameters for logout support.
- CSRF middleware now exempts `/oidc/logout` endpoint.
- `InitializeOAuth2Module` now returns `*DeviceCodeService` as 4th return value.
- `NewOAuth2Controller` now accepts `DeviceCodeManager` and `issuer` parameters.
- `OAuth2Controller.RegisterRoutes` now registers `/oauth2/device/code`, `/oauth2/device` endpoints.

- Translate all Chinese comments, doc-comments, error messages, and log strings to English across the entire codebase (78 files).
- Normalize sentinel errors to use `errors.New()` instead of static `fmt.Errorf()` across auth, account, and verification services.
- Add rollback error logging in `WithTransaction` and `WithTransactionIsolation` (previously silently discarded).
- Upgrade gouno dependency from v0.3.1 to v1.0.0.
- Upgrade bytedance/sonic from v1.14.0 to v1.15.1 for Go version compatibility.
- Router now registers all auth/OAuth2/OIDC routes.
- Update `config/test.yaml` — add auth section, fix Redis DSN to `127.0.0.1:6381` for host-based test access.
- JWT auth middleware now supports `access_token` query/form parameter in addition to Bearer header.
- OAuth2 consent page renders HTML form instead of JSON response.
- `AuthController.NewAuthController` now accepts `*SocialLoginService` parameter.
- `InitializeAuthModule` now returns `(*AuthService, *SocialLoginService)` and accepts OAuth provider configs.
- `InitializeAuthModule` now returns `*PasskeyService` as 6th return value (nil if WebAuthn not configured).
- `NewAuthService` accepts optional `*PasskeyService` parameter for MFA integration.
- `VerifyMFALogin` now accepts `mfaType` parameter (`"totp"` or `"passkey"`).
- `MFAService.IsMFAEnabled` now checks for passkeys in addition to TOTP.
- `AuthConfig` includes `WebAuthnRPID`, `WebAuthnRPName`, `WebAuthnRPOrigin` fields.
- JWT access tokens now signed with RS256 (RSA-2048) instead of HS256. HS256 tokens remain valid for backward compatibility.
- ID tokens now signed with RS256 and include `kid` header.
- JWKS endpoint now publishes RSA public key (`kty: "RSA"`) instead of symmetric key (`kty: "oct"`).
- `NewTokenService` now accepts a `*KeyService` parameter for RS256 signing.
- `NewJWKSService` now accepts a `*KeyService` instead of `[]byte` secret.
- `GetSecret()` replaced by `KeyService()` accessor on `TokenService`.
- `InitializeAuthModule` now returns `(*AuthService, *SocialLoginService, *VerificationService, *PasswordResetService, CredentialRepository)` and accepts `baseURL` parameter.
- `NewAuthController` now accepts `*PasswordResetService` parameter.
- `SessionService.CreateSession` now maintains `account_sessions:<accountID>` Redis Set index for account-level session management.
- `RegisterWebRouter` now accepts `*AdminController` parameter and registers `/api/admin` route group.
- Fix `Auditor` table name `audit_records` → `audit_record` to match migration.
- Fix `Auditor.Do` column name `did` → `account_id`.
- `NewAccountService` now accepts `*Auditor` parameter for audit logging.
- `NewAuthService` now accepts `*Auditor` parameter for audit logging.
- `InitializeAccountModule` now accepts `*Auditor` parameter.
- `InitializeAuthModule` now accepts `*Auditor` parameter.
- `AuthService.Logout` now requires `accountID` parameter for audit logging.

### Fixed

- Fix `WithTransaction` and `WithTransactionIsolation` not handling `panic(nil)` — now properly rolls back instead of silently committing.
- Fix CI: upgrade golangci-lint to v2.12.2 (v1 couldn't target Go 1.25), migrate config to v2 format.
- Fix CI: upgrade golangci-lint-action to v7 (v6 doesn't support golangci-lint v2).
- Fix CI: update auth integration test to match `InitializeAuthModule` 11-parameter signature (added `tokenSvc`).
- Fix CI: session unit test now reads Redis DSN from `GOUNO_REDIS_DSN` env var with localhost fallback.
- Fix CI: integration test DB connection closed by `runMigrations` — golang-migrate postgres driver's `Close()` closes the underlying `*sql.DB`.
- Fix CI: golangci-lint v2 config schema — `exclusions` under `linters`, `local-prefixes` as array, remove deprecated `gosimple`.
- Fix CI: JWT refresh test flaky due to second-precision `iat` — add 1s sleep before refresh.
- Fix `*string` format specifier in examples/account/main.go.
- Fix redundant newline in examples/metadata/main.go.
