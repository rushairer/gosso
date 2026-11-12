# ADR-0005: Session Cache Bounded Eviction

- **Status**: Accepted
- **Date**: 2026-06-22

## Context

The session validation hot path caches parsed `Session` objects in a `sync.Map` to avoid repeated JSON unmarshal from Redis. Under extreme session diversity (many unique sessions), this cache could grow without bound, leading to unbounded memory growth.

## Decision

Add a hard cap (`sessionCacheMaxSize = 8192`) on the in-memory session cache using an `atomic.Int32` counter.

- When the cache is at capacity, new entries are silently dropped (the session still exists in Redis; it just won't be cached locally)
- Stale entries (older than 2× sessionTTL) are periodically evicted by a background goroutine
- The counter is decremented on explicit `Delete`, `LoadAndDelete`, and stale eviction

### Alternatives considered

- **LRU cache (e.g., groupcache, ristretto)**: More complex, adds a dependency. Overkill for this use case where staleness detection already exists.
- **No cap**: Acceptable for low-traffic deployments but risky for production SSO servers handling many accounts.

## Consequences

- **Positive**: Memory usage is bounded; no OOM risk under extreme session diversity
- **Positive**: Zero dependencies added; uses only stdlib (`sync.Map`, `sync/atomic`)
- **Positive**: Redis remains the source of truth; dropped cache entries only add one Redis round-trip
- **Negative**: Under high diversity, cache hit rate may drop (acceptable since Redis GETEX is fast)
