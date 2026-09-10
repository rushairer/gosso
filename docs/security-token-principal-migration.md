# Access Token Principal Migration

The September 2026 security baseline treats OAuth access tokens as resource-specific credentials rather than substitutes for a Gosso account session.

## Machine clients

`client_credentials` requests must include `resource=<registered-resource-uri>`. The resulting token represents the client itself: `principal_type=client`, `sub=client_id`, and no owner `account_id`, user role/permission, session ID, `auth_time`, or `amr` is emitted.

## Authorization-code and refresh clients

Select the intended RFC 8707 resource during authorization. If `resource` is repeated during code exchange or refresh it must match the resource already bound to the authorization/refresh-token family. Gosso no longer expands an omitted resource into every entry of `allowed_resources`.

## Resource servers

Validate your configured `aud` in addition to signature, issuer, expiry/not-before, client identity where applicable, and required scopes. Keep application-local authorization independent from provider roles unless that mapping is an explicit product policy.

## Browser applications

Prefer a confidential Backend-for-Frontend. The browser keeps only the application's same-origin Secure/HttpOnly session cookie; the BFF performs authorization-code + PKCE exchange, refresh, resource calls, UserInfo and revocation. Raw provider access/refresh tokens should not be exposed to browser JavaScript.

## Gosso control plane

Password, profile, session, MFA, Passkey, OAuth client-management and administrator operations require the first-party `user_session` principal. Delegated and machine access tokens are not substitutes for that session.
