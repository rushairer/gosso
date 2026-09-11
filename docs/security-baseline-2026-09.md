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
- [x] Regression, integration, coverage, architecture, migration, vulnerability, container and Trivy gates green on the baseline and v1.6.1 patch merge candidates and final main commit.
- [x] `gosso-client` reviewed; `gosso-admin` and `gouno-blog` release-artifact compatibility verified against the final v1.6.1 baseline.
- [x] Version/changelog/release metadata updated through v1.6.1.
- [x] v1.6.0 baseline and v1.6.1 protocol-compatibility patch releases published after green CI.

## Closure evidence

Baseline implementation and release:

- Security baseline PR #31 was squash-merged at `5f94e5c0ececd236cf56d6694bc437a027e7da9e`, which is the immutable source commit for `v1.6.0`.
- `v1.6.0` published a multi-architecture image at `sha256:5c91647bdfe7c8de9dec8e40f882680c91883f9ba2dce6fd309f7f8f3d05f445` and Helm OCI chart at `sha256:7c57b6c0f6483dc810efe92efa1619dfc26fa6976d3cd7be77a6d234b3ed6585`.
- Release-pipeline hardening PR #33 pinned the GHCR-validated Helm version, added explicit Helm registry authentication, exact archive publication and remote OCI verification.

Final protocol compatibility patch:

- Blog release-artifact acceptance exposed that `/oauth2/revoke` was still passing through browser double-submit CSRF before RFC 7009 client authentication. PR #34 corrected that protocol boundary without relaxing CSRF on browser/session logout and was squash-merged at `0ec136f67b2fa165abbf77fedb5fdd50b5ebe69f`.
- The final Gosso main CI for that commit completed successfully, including unit/coverage and critical-package coverage, integration tests, lint, build, architecture invariants, migration rollback, `govulncheck`, `gosec`, multi-architecture Docker build and Trivy scanning.
- `v1.6.1` is fixed to source commit `0ec136f67b2fa165abbf77fedb5fdd50b5ebe69f`. Its multi-architecture image digest is `sha256:cf3c321279b9860bbbcf30735dcd0d3a3465151075420d8fa70d6d66e580838b`; its Helm OCI digest is `sha256:3b9d464e389dff4a8efc85d11a519cbcabb7d77a96eab7817ca504f147dc6f18`. The image was cosign-signed and published with CycloneDX/SPDX SBOMs and a CycloneDX attestation.

Downstream acceptance:

- `gosso-admin` PR #48 pinned its release compatibility gate to the exact v1.6.1 image digest and passed release boot/migrations, current seed policy, Discovery/JWKS, live user-session Admin API, production cookie-session attributes and Authorization Code + PKCE S256. It was squash-merged at `533c0cda1f0f04a73e62fbe07a26489e013373a9`.
- `gouno-blog` PR #42 pinned the confidential BFF acceptance gate to the exact v1.6.1 image digest and passed Authorization Code + PKCE with RFC 8707 resource binding, delegated-token claims, UserInfo audience isolation, refresh audience preservation, Secure/HttpOnly BFF flow handling, real HTTPS back-channel logout over the explicit Docker private-CIDR exception, and confidential-client RFC 7009 refresh-token revocation. It was squash-merged at `87eff6e6d7983e19e6bc9ed7f972b611c7a36210`.
- `gosso-client` already supported the required RFC 8707 `resource` contract; review found no security-driven package change or release was required.

Existing pre-baseline user-session tokens remain recognizable for their short remaining lifetime. Machine clients must send `resource=<registered-resource-uri>` when using `client_credentials` after this baseline.
