# Gosso release checklist

## Before creating an annotated tag

- Fetch origin and tags without force; preserve all existing tags and local work.
- Confirm clean worktree, final main SHA, absent target tag, and a dated CHANGELOG entry.
- Confirm tag, CHANGELOG, Chart version and Chart appVersion agree (v1.7.0 / 1.7.0 for this train).
- Confirm public Core v1.4.0 dependency and module checksums; no local replace or pseudo-version.
- Accept the exact final SHA's complete CI: unit/race and critical coverage, vet, lint, fail-closed gosec, govulncheck, PostgreSQL/Redis HTTP integration, migration cycle, architecture, Helm, Docker and security scans. A skipped PR-only commit-title job is not a security result.
- Review the administrator global OAuth2 client governance API: first-party live user-session principal, admin scope and role; preserve owner-scoped user routes, validation, reserved-scope controls, transactional optimistic updates and secret handling.
- Read docs/quality/release-security-disposition-2026-11.md; no broad scanner exclusions or reachable vulnerability suppression may be introduced.

## After tag publication (required for release completion)

- Verify the remote annotated tag peels to the accepted SHA; never rewrite it.
- Wait for the exact tag's Release workflow to complete successfully, including multi-arch image publication, post-signing exact-identity Cosign verification, both SBOM formats and Helm OCI push/read-back.
- Independently inspect the published linux/amd64 and linux/arm64 manifest and record its immutable digest.
- Independently verify that digest with issuer https://token.actions.githubusercontent.com and identity https://github.com/rushairer/gosso/.github/workflows/release.yml@refs/tags/v1.7.0.
- Download and validate SPDX/CycloneDX release attachments and the Helm OCI chart metadata; record evidence in the ecosystem audit.
- Verify the GitHub Release and public Go module proxy resolve the accepted SHA. No production deployment is implied.

Signing success alone is not signature verification. Main-channel images are development artifacts, never the evidence for a versioned release.
