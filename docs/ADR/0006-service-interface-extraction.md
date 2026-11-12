# ADR-0006: Service Interface Extraction

- **Status**: Accepted
- **Date**: 2026-06-22

## Context

Initially, only the `account` module defined a service interface (`AccountService`). The `session`, `token`, and `auth` modules exposed concrete struct types directly, making it impossible for callers to mock these services in tests without depending on the concrete implementation.

## Decision

Extract public interfaces for all major services:

- `SessionServiceInterface` (11 methods) in `internal/session/service/session_service_interface.go`
- `TokenServiceInterface` (13 methods) in `internal/token/service/token_service_interface.go`
- `AccountService` interface (already existed in `account_service.go`)
- `AuthOrchestrator` interface (already existed in auth module)

Each interface file contains only the interface definition and godoc comments — no implementation code.

### Naming convention

- Use `{ServiceName}Interface` when the concrete type is `{ServiceName}` (e.g., `SessionServiceInterface` for `SessionService`)
- This avoids import cycle issues and makes the dependency direction explicit

## Consequences

- **Positive**: Callers can mock services without depending on concrete types
- **Positive**: Interface files serve as a contract documentation
- **Positive**: Enables future DI framework integration (e.g., wire)
- **Negative**: Interface files must be kept in sync with concrete method signatures
- **Negative**: Go convention prefers small interfaces; these are necessarily large due to the service surface area
