package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/rushairer/gosso/internal/session/domain"
	"github.com/rushairer/gosso/internal/utility"
)

// RevokeSession revokes a specific session (with ownership check).
func (s *SessionService) RevokeSession(ctx context.Context, accountID string, sessionID string) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.AccountID != accountID {
		return ErrSessionAccessDenied
	}

	// Revoke refresh tokens for this session before deleting the session key.
	// Prevents orphaned tokens that could still be rotated after session deletion.
	if s.tokenRevoker != nil {
		if err := s.tokenRevoker.RevokeAllForSession(ctx, sessionID); err != nil {
			return fmt.Errorf("revoke tokens for session: %w", err)
		}
	} else {
		s.logger.Warn("Token revoker not configured, skipping token revocation during session revoke",
			zap.String("session_id", utility.MaskOpaqueID(sessionID)))
	}

	// Delete session key
	key := s.buildSessionKey(sessionID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to delete session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return fmt.Errorf("delete session: %w", err)
	}

	// Remove from account index
	indexKey := s.buildAccountSessionsKey(accountID)
	if err := s.redis.SRem(ctx, indexKey, sessionID); err != nil {
		s.logger.Warn("Failed to remove session from account index during revocation",
			zap.String("session_id", utility.MaskOpaqueID(sessionID)),
			zap.String("account_id", utility.MaskOpaqueID(accountID)),
			zap.Error(err))
	}

	s.logger.Info("Session revoked",
		zap.String("session_id", utility.MaskOpaqueID(sessionID)),
		zap.String("account_id", utility.MaskOpaqueID(accountID)))
	return nil
}

// RevokeAllForAccount revokes all sessions and tokens for the given account.
// Uses a Lua script to atomically read the session set and delete the index,
// preventing a TOCTOU race where new sessions created between SMembers and Del
// would be orphaned.
func (s *SessionService) RevokeAllForAccount(ctx context.Context, accountID string) error {
	indexKey := s.buildAccountSessionsKey(accountID)

	// Atomically read all session IDs and delete the index.
	// Any sessions created after this point will produce a fresh index entry.
	result, err := s.redis.RunScript(ctx, revokeAccountSessionsScript, []string{indexKey}).StringSlice()
	if err != nil && !errors.Is(err, redis.Nil) {
		s.logger.Error("Failed to atomically read and delete account sessions index",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
		return fmt.Errorf("revoke account sessions: %w", err)
	}

	sessionIDs := result

	// Revoke tokens for each session before deleting session keys.
	// Token revocation is idempotent — if a session has no tokens, this is a no-op.
	// Uses errgroup to parallelize Redis round-trips for each session's token revocation.
	if s.tokenRevoker != nil {
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(min(len(sessionIDs), runtime.NumCPU()))
		for _, sid := range sessionIDs {
			g.Go(func() error {
				if err := s.tokenRevoker.RevokeAllForSession(gctx, sid); err != nil {
					s.logger.Warn("Failed to revoke tokens for session during account revocation",
						zap.String("session_id", utility.MaskOpaqueID(sid)), zap.Error(err))
				}
				return nil // non-fatal: warning already logged
			})
		}
		_ = g.Wait() // all goroutines return nil; wait for completion
	} else {
		s.logger.Warn("Token revoker not configured, skipping token revocation for account sessions",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Int("count", len(sessionIDs)))
	}

	// Delete individual session keys.
	// Deleting a key that doesn't exist is a no-op in Redis.
	if len(sessionIDs) > 0 {
		keys := make([]string, len(sessionIDs))
		for i, sid := range sessionIDs {
			keys[i] = sessionKeyPrefix + sid
		}
		if err := s.redis.Del(ctx, keys...); err != nil {
			s.logger.Error("Failed to delete account sessions", zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
			return fmt.Errorf("delete account sessions: %w", err)
		}
	}

	s.logger.Info("All sessions revoked for account",
		zap.String("account_id", utility.MaskOpaqueID(accountID)),
		zap.Int("count", len(sessionIDs)))

	return nil
}

// ListSessionsByAccount lists all active sessions for the given account.
func (s *SessionService) ListSessionsByAccount(ctx context.Context, accountID string) ([]*domain.Session, error) {
	indexKey := s.buildAccountSessionsKey(accountID)

	sessionIDs, err := s.redis.SMembers(ctx, indexKey)
	if err != nil {
		return nil, fmt.Errorf("get account sessions: %w", err)
	}

	if len(sessionIDs) == 0 {
		return nil, nil
	}

	// Build keys
	type sessionEntry struct {
		rawID string
		key   string
	}
	entries := make([]sessionEntry, 0, len(sessionIDs))
	for _, sid := range sessionIDs {
		entries = append(entries, sessionEntry{rawID: sid, key: s.buildSessionKey(sid)})
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Pipeline batch GET
	rdb := s.redis.GetClient()
	pipe := rdb.Pipeline()
	cmds := make([]*redis.StringCmd, len(entries))
	for i, entry := range entries {
		cmds[i] = pipe.Get(ctx, entry.key)
	}
	// Pipeline batch GET — pipe.Exec returns the first per-command error,
	// but individual command results are checked below. A non-redis.Nil error
	// here typically means a network/connection problem affecting all commands.
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		s.logger.Error("Pipeline session fetch failed", zap.Error(err), zap.String("account_id", utility.MaskOpaqueID(accountID)))
		return nil, fmt.Errorf("pipeline session fetch: %w", err)
	}

	var sessions []*domain.Session
	staleIDs := make([]string, 0, len(entries))
	for i, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil {
			// Fallback: retry with a direct GET. This handles two cases:
			// 1. Production: a key expired between SMembers and pipeline.Exec — retry
			//    confirms it's genuinely gone (costs one extra round-trip per stale key).
			// 2. Tests: miniredis returns redis.Nil for ALL keys when any sibling key
			//    is missing. Direct GET bypasses this quirk.
			data, err = s.redis.Get(ctx, entries[i].key)
			if err != nil {
				staleIDs = append(staleIDs, entries[i].rawID)
				continue
			}
		}
		var session domain.Session
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			staleIDs = append(staleIDs, entries[i].rawID)
			continue
		}
		if !s.isSessionActive(&session) {
			s.forceExpireSession(ctx, entries[i].rawID, indexKey)
			continue
		}
		sessions = append(sessions, &session)
	}

	// Clean up stale index entries using a pipeline to batch SREM calls
	// into a single Redis round-trip instead of one per stale entry.
	if len(staleIDs) > 0 {
		pipe := rdb.Pipeline()
		for _, sid := range staleIDs {
			pipe.SRem(ctx, indexKey, sid)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			s.logger.Warn("Failed to remove stale session index entries via pipeline",
				zap.Int("count", len(staleIDs)),
				zap.String("account_id", utility.MaskOpaqueID(accountID)),
				zap.Error(err))
		}
	}

	return sessions, nil
}

// EnforceSessionLimit ensures that the account does not exceed the maximum
// number of concurrent sessions. Uses an atomic Lua script to eliminate the
// TOCTOU window between reading the session list and deleting excess sessions.
func (s *SessionService) EnforceSessionLimit(ctx context.Context, accountID string) error {
	return s.enforceSessionLimit(ctx, accountID, "")
}

func (s *SessionService) enforceSessionLimit(ctx context.Context, accountID, protectedSessionID string) error {
	if s.maxSessions <= 0 {
		return nil
	}

	if s.tokenRevoker == nil {
		return ErrTokenRevokerNotConfigured
	}

	indexKey := s.buildAccountSessionsKey(accountID)
	rdb := s.redis.GetClient()

	raw, err := evictOldestSessionsScript.Run(ctx, rdb, []string{indexKey}, s.maxSessions, protectedSessionID).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("evict oldest sessions: %w", err)
	}

	evictedIDs, ok := raw.([]interface{})
	if !ok {
		s.logger.Error("Unexpected type from evict oldest sessions script",
			zap.Any("result", raw))
		return fmt.Errorf("evict oldest sessions: unexpected result type %T", raw)
	}
	if len(evictedIDs) == 0 {
		return nil
	}

	// Revoke tokens for evicted sessions (requires external calls, cannot be done in Lua)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(min(len(evictedIDs), runtime.NumCPU()))
	for _, id := range evictedIDs {
		sid, _ := id.(string)
		if sid == "" {
			continue
		}
		s.logger.Info("Evicted oldest session due to limit",
			zap.String("session_id", utility.MaskOpaqueID(sid)),
			zap.String("account_id", utility.MaskOpaqueID(accountID)))

		g.Go(func() error {
			if err := s.tokenRevoker.RevokeAllForSession(gctx, sid); err != nil {
				s.logger.Warn("Failed to revoke tokens for evicted session",
					zap.String("session_id", utility.MaskOpaqueID(sid)), zap.Error(err))
			}
			return nil // non-fatal: warning already logged
		})
	}
	_ = g.Wait() // all goroutines return nil; wait for completion

	return nil
}
