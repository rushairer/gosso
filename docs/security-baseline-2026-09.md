# Security Baseline — September 2026

This is the authoritative checklist for the September 2026 Gosso security hardening cycle.

Access tokens distinguish `user_session`, `delegated_user`, and `client` principals. New JWT access tokens use `typ=at+jwt` and `principal_type`; machine tokens represent the client itself and do not carry owner-account authority. Authorization-code and refresh-token grants preserve one selected RFC 8707 resource, while `client_credentials` requires an explicitly registered resource.

Gosso account-security and administrative control-plane operations require a live first-party `user_session`; a valid delegated or machine JWT is not sufficient account authority.

Security-sensitive authorization follows this trust order:

`principal type -> token type -> audience -> scope -> live session -> authentication assurance -> resource authorization`

## Checklist

- [x] Explicit access-token principal classes.
- [x] Machine token / owner-account separation.
- [x] RFC 8707 resource binding without implicit multi-audience expansion.
- [x] `typ=at+jwt` issuance and conflicting-type rejection.
- [x] Account-control user-session enforcement.
- [x] Back-channel logout private/link-local/metadata egress deny-by-default.
- [x] Real signing-key rotation with verification/JWKS overlap.
- [x] Password/security documentation aligned to Argon2id runtime behavior.
- [ ] Regression and integration CI green on merge candidate.
- [x] gosso-client, gosso-admin, and gouno-blog compatibility verified.
- [x] Version/changelog/release metadata updated for v1.6.0.
- [ ] v1.6.0 release published after the merge candidate passes CI.

Existing pre-baseline user-session tokens remain recognizable for their short remaining lifetime. Machine clients must send `resource=<registered-resource-uri>` when using `client_credentials` after this baseline.
