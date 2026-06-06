package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/session/domain"
	"github.com/rushairer/gosso/utility"
)

const (
	// SessionKeyPrefix is the Redis key prefix for sessions.
	SessionKeyPrefix = "session:"
	// AccountSessionsPrefix is the Redis key prefix for account-session index.
	AccountSessionsPrefix = "account_sessions:"
	// DefaultSessionTTL is the default session expiry duration (24 hours).
	DefaultSessionTTL = 24 * time.Hour
	// DefaultMaxSessions is the default maximum concurrent sessions per account.
	DefaultMaxSessions = 10
)

// revokeAccountSessionsScript atomically reads all session IDs from the
// account_sessions set and deletes the set in a single EVAL call.
// This eliminates the TOCTOU window between SMembers and Del where new
// sessions can be created and then orphaned.
// KEYS[1] = account_sessions:{accountID}
// Returns: array of session ID strings (may be empty)
var revokeAccountSessionsScript = redis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
redis.call('DEL', KEYS[1])
return members
`)

// TokenRevoker revokes all tokens for a given session.
type TokenRevoker interface {
	RevokeAllForSession(ctx context.Context, sessionID string) error
}

// SessionService manages user sessions backed by Redis.
type SessionService struct {
	redis       *cache.RedisClient
	logger      *zap.Logger
	sessionTTL  time.Duration
	maxSessions int
	tokenRevoker TokenRevoker
}

// NewSessionService creates a new session service instance.
func NewSessionService(redis *cache.RedisClient, logger *zap.Logger) *SessionService {
	logger = utility.EnsureLogger(logger)

	return &SessionService{
		redis:       redis,
		logger:      logger,
		sessionTTL:  DefaultSessionTTL,
		maxSessions: DefaultMaxSessions,
	}
}

// SetTokenRevoker sets the token revoker for cascading token revocation.
// Must be called during initialization; not safe for concurrent use.
func (s *SessionService) SetTokenRevoker(revoker TokenRevoker) {
	s.tokenRevoker = revoker
}

// SetMaxSessions sets the maximum concurrent sessions per account.
// Must be called during initialization; not safe for concurrent use.
func (s *SessionService) SetMaxSessions(n int) {
	if n < 0 {
		return
	}
	s.maxSessions = n
}

// SetSessionTTL sets the session expiry duration.
// Must be called during initialization; not safe for concurrent use.
func (s *SessionService) SetSessionTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s.sessionTTL = ttl
}

// CreateSession creates a new session.
func (s *SessionService) CreateSession(ctx context.Context, session *domain.Session) error {
	if session.ID == "" {
		session.ID = uuid.New().String()
	}

	now := time.Now()
	session.CreatedAt = now
	session.LastActiveAt = now

	// Serialize session data
	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", session.ID))
		return fmt.Errorf("marshal session: %w", err)
	}

	key := s.buildSessionKey(session.ID)
	if err := s.redis.Set(ctx, key, data, s.sessionTTL); err != nil {
		s.logger.Error("Failed to create session", zap.Error(err), zap.String("session_id", session.ID))
		return fmt.Errorf("create session: %w", err)
	}

	// Maintain account session index (SADD + EXPIRE atomically via Lua)
	indexKey := s.buildAccountSessionsKey(session.AccountID)
	if err := s.redis.SAddWithTTL(ctx, indexKey, session.ID, s.sessionTTL); err != nil {
		s.logger.Warn("Failed to index session by account", zap.Error(err), zap.String("session_id", session.ID))
	}

	// Enforce maximum concurrent session limit
	if err := s.EnforceSessionLimit(ctx, session.AccountID); err != nil {
		s.logger.Warn("Failed to enforce session limit", zap.Error(err),
			zap.String("account_id", session.AccountID))
	}

	s.logger.Info("Session created",
		zap.String("session_id", session.ID),
		zap.String("account_id", session.AccountID),
		zap.Duration("ttl", s.sessionTTL))

	return nil
}

// GetSession retrieves session information.
func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	key := s.buildSessionKey(sessionID)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		s.logger.Error("Failed to get session", zap.Error(err), zap.String("session_id", sessionID))
		return nil, fmt.Errorf("get session: %w", err)
	}

	var session domain.Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		s.logger.Error("Failed to unmarshal session", zap.Error(err), zap.String("session_id", sessionID))
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &session, nil
}

// UpdateSession updates session information atomically.
// Uses a Lua script to ensure the session still exists before overwriting,
// preventing resurrection of sessions that expired between the read and write.
func (s *SessionService) UpdateSession(ctx context.Context, session *domain.Session) error {
	// Load current session data for UpdateActivity
	if _, err := s.GetSession(ctx, session.ID); err != nil {
		return err
	}

	session.UpdateActivity()

	// Serialize session data
	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", session.ID))
		return fmt.Errorf("marshal session: %w", err)
	}

	// Atomically set only if the session still exists (prevents TOCTOU resurrection)
	key := s.buildSessionKey(session.ID)
	ok, err := s.redis.SetIfExists(ctx, key, data, s.sessionTTL)
	if err != nil {
		s.logger.Error("Failed to update session", zap.Error(err), zap.String("session_id", session.ID))
		return fmt.Errorf("update session: %w", err)
	}
	if !ok {
		s.logger.Debug("Session expired during update, skipping", zap.String("session_id", session.ID))
		return fmt.Errorf("session %s no longer exists", session.ID)
	}

	// Refresh the account sessions index TTL to prevent it from expiring before the session
	indexKey := s.buildAccountSessionsKey(session.AccountID)
	if err := s.redis.Expire(ctx, indexKey, s.sessionTTL); err != nil {
		s.logger.Warn("Failed to refresh account sessions index TTL", zap.String("account_id", session.AccountID), zap.Error(err))
	}

	s.logger.Debug("Session updated", zap.String("session_id", session.ID))
	return nil
}

// DeleteSession deletes a session and removes it from the account session index.
func (s *SessionService) DeleteSession(ctx context.Context, sessionID string) error {
	// Load session to get accountID for index cleanup.
	// If the session has already expired and GetSession fails, we still
	// attempt the index cleanup using whatever data we can obtain.
	session, getErr := s.GetSession(ctx, sessionID)

	key := s.buildSessionKey(sessionID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to delete session", zap.Error(err), zap.String("session_id", sessionID))
		return fmt.Errorf("delete session: %w", err)
	}

	// Always attempt to clean up the account session index.
	// If the session was loaded, use its accountID. Otherwise, the stale
	// index entry will be cleaned up lazily by ListSessionsByAccount.
	if session != nil {
		indexKey := s.buildAccountSessionsKey(session.AccountID)
		if err := s.redis.SRem(ctx, indexKey, sessionID); err != nil {
			s.logger.Warn("Failed to remove session from account index",
				zap.String("session_id", sessionID), zap.Error(err))
		}
	} else if getErr != nil {
		s.logger.Debug("Session data unavailable for index cleanup, stale entry will be cleaned by ListSessionsByAccount",
			zap.String("session_id", sessionID), zap.Error(getErr))
	}

	s.logger.Info("Session deleted", zap.String("session_id", sessionID))
	return nil
}

// RefreshSession refreshes the session expiration.
func (s *SessionService) RefreshSession(ctx context.Context, sessionID string) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.UpdateActivity()

	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", sessionID))
		return fmt.Errorf("marshal session: %w", err)
	}

	key := s.buildSessionKey(sessionID)
	ok, err := s.redis.SetIfExists(ctx, key, data, s.sessionTTL)
	if err != nil {
		s.logger.Error("Failed to refresh session", zap.Error(err), zap.String("session_id", sessionID))
		return fmt.Errorf("refresh session: %w", err)
	}
	if !ok {
		return fmt.Errorf("session %s no longer exists", sessionID)
	}

	return nil
}

// ValidateSession validates whether a session is still active.
func (s *SessionService) ValidateSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Check if session has expired
	if session.IsExpired(s.sessionTTL) {
		s.logger.Warn("Session expired", zap.String("session_id", sessionID))
		// Delete the expired session
		_ = s.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	return session, nil
}

// buildSessionKey builds the Redis key for a session.
func (s *SessionService) buildSessionKey(sessionID string) string {
	return fmt.Sprintf("%s%s", SessionKeyPrefix, sessionID)
}

// buildAccountSessionsKey builds the Redis key for the account session index.
func (s *SessionService) buildAccountSessionsKey(accountID string) string {
	return fmt.Sprintf("%s%s", AccountSessionsPrefix, accountID)
}

// RevokeAllForAccount revokes all sessions and tokens for the given account.
// Uses a Lua script to atomically read the session set and delete the index,
// preventing a TOCTOU race where new sessions created between SMembers and Del
// would be orphaned.
func (s *SessionService) RevokeAllForAccount(ctx context.Context, accountID string) error {
	indexKey := s.buildAccountSessionsKey(accountID)

	// Atomically read all session IDs and delete the index.
	// Any sessions created after this point will produce a fresh index entry.
	result, err := revokeAccountSessionsScript.Run(ctx, s.redis.GetClient(), []string{indexKey}).StringSlice()
	if err != nil && err != redis.Nil {
		s.logger.Error("Failed to atomically read and delete account sessions index",
			zap.String("account_id", accountID), zap.Error(err))
		return fmt.Errorf("revoke account sessions: %w", err)
	}

	sessionIDs := result

	// Revoke tokens for each session before deleting session keys.
	// Token revocation is idempotent — if a session has no tokens, this is a no-op.
	if s.tokenRevoker != nil {
		for _, sid := range sessionIDs {
			if err := s.tokenRevoker.RevokeAllForSession(ctx, sid); err != nil {
				s.logger.Warn("Failed to revoke tokens for session during account revocation",
					zap.String("session_id", sid), zap.Error(err))
			}
		}
	}

	// Delete individual session keys.
	// Deleting a key that doesn't exist is a no-op in Redis.
	if len(sessionIDs) > 0 {
		keys := make([]string, len(sessionIDs))
		for i, sid := range sessionIDs {
			keys[i] = SessionKeyPrefix + sid
		}
		if err := s.redis.Del(ctx, keys...); err != nil {
			s.logger.Error("Failed to delete account sessions", zap.String("account_id", accountID), zap.Error(err))
			return fmt.Errorf("delete account sessions: %w", err)
		}
	}

	s.logger.Info("All sessions revoked for account",
		zap.String("account_id", accountID),
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
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		s.logger.Error("Pipeline session fetch failed", zap.Error(err), zap.String("account_id", accountID))
		return nil, fmt.Errorf("pipeline session fetch: %w", err)
	}

	var sessions []*domain.Session
	staleIDs := make([]string, 0)
	for i, cmd := range cmds {
		data, err := cmd.Result()
		if err != nil {
			staleIDs = append(staleIDs, entries[i].rawID)
			continue
		}
		var session domain.Session
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			staleIDs = append(staleIDs, entries[i].rawID)
			continue
		}
		sessions = append(sessions, &session)
	}

	// Clean up stale index entries
	for _, sid := range staleIDs {
		if err := s.redis.SRem(ctx, indexKey, sid); err != nil {
			s.logger.Warn("Failed to remove stale session index entry", zap.String("session_id", sid), zap.Error(err))
		}
	}

	return sessions, nil
}

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
			s.logger.Warn("Failed to revoke tokens for session during revocation",
				zap.String("session_id", sessionID),
				zap.String("account_id", accountID),
				zap.Error(err))
		}
	}

	// Delete session key
	key := s.buildSessionKey(sessionID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to delete session", zap.Error(err), zap.String("session_id", sessionID))
		return fmt.Errorf("delete session: %w", err)
	}

	// Remove from account index
	indexKey := s.buildAccountSessionsKey(accountID)
	if err := s.redis.SRem(ctx, indexKey, sessionID); err != nil {
		s.logger.Warn("Failed to remove session from account index during revocation",
			zap.String("session_id", sessionID),
			zap.String("account_id", accountID),
			zap.Error(err))
	}

	s.logger.Info("Session revoked",
		zap.String("session_id", sessionID),
		zap.String("account_id", accountID))
	return nil
}

// EnforceSessionLimit checks and enforces the maximum concurrent session limit.
// When the limit is exceeded, the oldest sessions are revoked.
// Session key deletions are batched into a single Redis DEL call for efficiency.
func (s *SessionService) EnforceSessionLimit(ctx context.Context, accountID string) error {
	if s.maxSessions <= 0 {
		return nil
	}

	sessions, err := s.ListSessionsByAccount(ctx, accountID)
	if err != nil {
		return fmt.Errorf("list sessions: %w", err)
	}

	if len(sessions) <= s.maxSessions {
		return nil
	}

	// Sort by LastActiveAt and revoke the oldest
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastActiveAt.Before(sessions[j].LastActiveAt)
	})

	toRemove := len(sessions) - s.maxSessions
	keys := make([]string, 0, toRemove)

	for i := 0; i < toRemove; i++ {
		sid := sessions[i].ID
		s.logger.Info("Revoking old session due to limit",
			zap.String("session_id", sid),
			zap.String("account_id", accountID))

		if s.tokenRevoker != nil {
			if err := s.tokenRevoker.RevokeAllForSession(ctx, sid); err != nil {
				s.logger.Warn("Failed to revoke tokens for session during limit enforcement",
					zap.String("session_id", sid), zap.Error(err))
			}
		}
		keys = append(keys, s.buildSessionKey(sid))
	}

	// Batch delete all excess session keys in a single Redis call
	if len(keys) > 0 {
		if err := s.redis.Del(ctx, keys...); err != nil {
			s.logger.Error("Failed to batch delete sessions", zap.String("account_id", accountID), zap.Error(err))
			return fmt.Errorf("batch delete sessions: %w", err)
		}
	}

	// Remove excess sessions from the account index
	indexKey := s.buildAccountSessionsKey(accountID)
	for i := 0; i < toRemove; i++ {
		if err := s.redis.SRem(ctx, indexKey, sessions[i].ID); err != nil {
			s.logger.Warn("Failed to remove session from account index",
				zap.String("session_id", sessions[i].ID), zap.Error(err))
		}
	}

	return nil
}

// Error definitions
var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpired      = errors.New("session expired")
	ErrSessionAccessDenied = errors.New("session not found or access denied")
)
