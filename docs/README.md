# GOSSO Documentation Index

GOSSO documentation has one canonical directory: **`docs/`**. The former `doc/` directory was consolidated without discarding the ADR, runbook, or integration history. The [README](../README.md) and [中文 README](../README.zh-CN.md) are the entrypoints for installing the service.

## Current implementation and operating contracts

| Purpose | Canonical document |
| --- | --- |
| Capability module, error handling, repository, transaction, security, tests | [Architecture Invariants](ARCHITECTURE_INVARIANTS.md) |
| API versioning | [API_VERSIONING](API_VERSIONING.md) and [API stability](api-stability.md) |
| Deployment and incident operations | [Operator Guide](OPERATOR_GUIDE.md) / [运维指南](OPERATOR_GUIDE.zh-CN.md) |
| Backup and restore | [Backup / Restore](BACKUP_RESTORE.md) |
| Consumer OAuth/OIDC integration | [Integrator Guide](INTEGRATOR_GUIDE.md) — current code-backed flow and security responsibilities; obsolete runnable examples were retired to Git history |
| Environment and database conventions | [Environment configuration](environment-config.md) / [Database design decisions](DATABASE_DESIGN_DECISIONS.md) |
| Signing-key operations | [Security key rotation](security-key-rotation.md) |
| Machine-readable API | [OpenAPI](openapi.yaml) with generated [Swagger bindings](swagger.go) |

**Source of truth:** The current route/controller/service code, `config/`, database migrations and deployment manifests take precedence over outdated examples or recorded plans. The OpenAPI/Swagger files remain at their existing `docs/` paths because they are generated artifacts with consumers; do not move or hand-edit them as part of a directory tidy.

## Decision and historical evidence (retain for traceability)

- [ADR directory](ADR/) records numbered architecture decisions; once accepted, do not retroactively rewrite the original decision context. Add a superseding ADR instead.
- [Metadata type decision](metadata-type-decision.md), [MFA migration](mfa-api-migration.md), [2026-09 security baseline](security-baseline-2026-09.md), [token principal migration](security-token-principal-migration.md) and [2026-11 release security disposition](quality/release-security-disposition-2026-11.md) are dated or scoped records. They do not by themselves describe a running current production deployment.
- `CHANGELOG.md` in the repository root is a chronological release record. Keep historical versions intact; use `[Unreleased]` only for genuinely unshipped changes.

## Maintenance rules

1. Add new hand-maintained documentation under `docs/`; no second `doc/` tree.
2. Update internal Markdown links, root README, AGENTS, CODEOWNERS and quality-check references together when moving a document.
3. Do not remove migration, recovery or release evidence just because a task was completed; preserve it as an indexed dated record, and keep present-tense task lists separate.
4. Verify cross-document links and run relevant architecture checks before promoting any code-affecting contract changes.
