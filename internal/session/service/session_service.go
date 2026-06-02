package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/session/domain"
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

// SessionService manages user sessions backed by Redis.
type SessionService struct {
	redis       *cache.RedisClient
	logger      *zap.Logger
	sessionTTL  time.Duration
	maxSessions int
}

// NewSessionService creates a new session service instance.
func NewSessionService(redis *cache.RedisClient, logger *zap.Logger) *SessionService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &SessionService{
		redis:       redis,
		logger:      logger,
		sessionTTL:  DefaultSessionTTL,
		maxSessions: DefaultMaxSessions,
	}
}

// SetMaxSessions sets the maximum concurrent sessions per account.
func (s *SessionService) SetMaxSessions(n int) {
	s.maxSessions = n
}

// SetSessionTTL sets the session expiry duration.
func (s *SessionService) SetSessionTTL(ttl time.Duration) {
	s.sessionTTL = ttl
}

// CreateSession creates a new session.
func (s *SessionService) CreateSession(ctx context.Context, session *domain.Session) error {
	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}

	now := time.Now()
	session.CreatedAt = now
	session.LastActiveAt = now

	// Serialize session data
	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", session.ID.String()))
		return fmt.Errorf("marshal session: %w", err)
	}

	key := s.buildSessionKey(session.ID)
	if err := s.redis.Set(ctx, key, data, s.sessionTTL); err != nil {
		s.logger.Error("Failed to create session", zap.Error(err), zap.String("session_id", session.ID.String()))
		return fmt.Errorf("create session: %w", err)
	}

	// Maintain account session index
	indexKey := s.buildAccountSessionsKey(session.AccountID.String())
	if err := s.redis.SAdd(ctx, indexKey, session.ID.String()); err != nil {
		s.logger.Warn("Failed to index session by account", zap.Error(err), zap.String("session_id", session.ID.String()))
	}
	_ = s.redis.Expire(ctx, indexKey, s.sessionTTL)

	// Enforce maximum concurrent session limit
	s.EnforceSessionLimit(ctx, session.AccountID.String())

	s.logger.Info("Session created",
		zap.String("session_id", session.ID.String()),
		zap.String("account_id", session.AccountID.String()),
		zap.Duration("ttl", s.sessionTTL))

	return nil
}

// GetSession retrieves session information.
func (s *SessionService) GetSession(ctx context.Context, sessionID uuid.UUID) (*domain.Session, error) {
	key := s.buildSessionKey(sessionID)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		s.logger.Error("Failed to get session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return nil, fmt.Errorf("get session: %w", err)
	}

	var session domain.Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		s.logger.Error("Failed to unmarshal session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &session, nil
}

// UpdateSession updates session information.
func (s *SessionService) UpdateSession(ctx context.Context, session *domain.Session) error {
	// Verify the session exists first
	if _, err := s.GetSession(ctx, session.ID); err != nil {
		return err
	}

	session.UpdateActivity()

	// Serialize session data
	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", session.ID.String()))
		return fmt.Errorf("marshal session: %w", err)
	}

	key := s.buildSessionKey(session.ID)
	if err := s.redis.Set(ctx, key, data, s.sessionTTL); err != nil {
		s.logger.Error("Failed to update session", zap.Error(err), zap.String("session_id", session.ID.String()))
		return fmt.Errorf("update session: %w", err)
	}

	s.logger.Debug("Session updated", zap.String("session_id", session.ID.String()))
	return nil
}

// DeleteSession deletes a session.
func (s *SessionService) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	key := s.buildSessionKey(sessionID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to delete session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return fmt.Errorf("delete session: %w", err)
	}

	s.logger.Info("Session deleted", zap.String("session_id", sessionID.String()))
	return nil
}

// RefreshSession refreshes the session expiration.
func (s *SessionService) RefreshSession(ctx context.Context, sessionID uuid.UUID) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.UpdateActivity()
	return s.UpdateSession(ctx, session)
}

// ValidateSession validates whether a session is still active.
func (s *SessionService) ValidateSession(ctx context.Context, sessionID uuid.UUID) (*domain.Session, error) {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Check if session has expired
	if session.IsExpired(s.sessionTTL) {
		s.logger.Warn("Session expired", zap.String("session_id", sessionID.String()))
		// Delete the expired session
		_ = s.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	return session, nil
}

// buildSessionKey builds the Redis key for a session.
func (s *SessionService) buildSessionKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s%s", SessionKeyPrefix, sessionID.String())
}

// buildAccountSessionsKey builds the Redis key for the account session index.
func (s *SessionService) buildAccountSessionsKey(accountID string) string {
	return fmt.Sprintf("%s%s", AccountSessionsPrefix, accountID)
}

// RevokeAllForAccount revokes all sessions for the given account.
func (s *SessionService) RevokeAllForAccount(ctx context.Context, accountID string) error {
	indexKey := s.buildAccountSessionsKey(accountID)

	sessionIDs, err := s.redis.SMembers(ctx, indexKey)
	if err != nil {
		s.logger.Error("Failed to get account sessions", zap.String("account_id", accountID), zap.Error(err))
		return fmt.Errorf("get account sessions: %w", err)
	}

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

	// Delete the index itself
	if err := s.redis.Del(ctx, indexKey); err != nil {
		s.logger.Warn("Failed to delete account sessions index", zap.String("account_id", accountID), zap.Error(err))
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

	var sessions []*domain.Session
	for _, sid := range sessionIDs {
		sessionUUID, err := uuid.Parse(sid)
		if err != nil {
			continue
		}
		session, err := s.GetSession(ctx, sessionUUID)
		if err != nil {
			// Session expired or not found; remove from index
			_ = s.redis.SRem(ctx, indexKey, sid)
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// RevokeSession revokes a specific session (with ownership check).
func (s *SessionService) RevokeSession(ctx context.Context, accountID string, sessionID uuid.UUID) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.AccountID.String() != accountID {
		return fmt.Errorf("session does not belong to account")
	}

	// Remove from index
	indexKey := s.buildAccountSessionsKey(accountID)
	_ = s.redis.SRem(ctx, indexKey, sessionID.String())

	return s.DeleteSession(ctx, sessionID)
}

// EnforceSessionLimit checks and enforces the maximum concurrent session limit.
// When the limit is exceeded, the oldest sessions are revoked.
func (s *SessionService) EnforceSessionLimit(ctx context.Context, accountID string) {
	if s.maxSessions <= 0 {
		return
	}

	sessions, err := s.ListSessionsByAccount(ctx, accountID)
	if err != nil {
		return
	}

	if len(sessions) <= s.maxSessions {
		return
	}

	// Sort by LastActiveAt and revoke the oldest
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastActiveAt.Before(sessions[j].LastActiveAt)
	})

	// Revoke excess old sessions
	toRemove := len(sessions) - s.maxSessions
	for i := 0; i < toRemove; i++ {
		s.logger.Info("Revoking old session due to limit",
			zap.String("session_id", sessions[i].ID.String()),
			zap.String("account_id", accountID))
		_ = s.RevokeSession(ctx, accountID, sessions[i].ID)
	}
}

// Error definitions
var (
	ErrSessionNotFound = fmt.Errorf("session not found")
	ErrSessionExpired  = fmt.Errorf("session expired")
)
