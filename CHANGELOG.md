# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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

### Changed

- Upgrade gouno dependency from v0.3.1 to v1.0.0.
- Upgrade bytedance/sonic from v1.14.0 to v1.15.1 for Go version compatibility.
- Router now registers all auth/OAuth2/OIDC routes.
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

- Fix `*string` format specifier in examples/account/main.go.
- Fix redundant newline in examples/metadata/main.go.
