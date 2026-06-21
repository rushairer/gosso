package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/session/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	// sessionKeyPrefix is the Redis key prefix for sessions.
	sessionKeyPrefix = "session:"
	// accountSessionsPrefix is the Redis key prefix for account-session index.
	accountSessionsPrefix = "account_sessions:"
	// DefaultSessionTTL is the default session expiry duration (24 hours).
	DefaultSessionTTL = 24 * time.Hour
	// DefaultMaxSessions is the default maximum concurrent sessions per account.
	DefaultMaxSessions = 10
	// DefaultMaxSessionAge is the default absolute maximum session lifetime (7 days).
	DefaultMaxSessionAge = 7 * 24 * time.Hour
	// maxCacheCleanupInterval caps the cache cleanup sweep interval so that
	// stale entries don't accumulate for too long when sessionTTL is very high
	// (e.g., 24h). Without this cap, a system processing many unique sessions
	// with a 24h TTL would only sweep stale entries every ~72h (3 * TTL).
	maxCacheCleanupInterval = 1 * time.Hour
)

// TokenRevoker revokes all tokens for a given session.
type TokenRevoker interface {
	RevokeAllForSession(ctx context.Context, sessionID string) error
}

// SessionConfig holds configuration for SessionService.
// Prefer passing this to NewSessionServiceWithConfig over using individual setters.
type SessionConfig struct {
	// SessionTTL is the session expiry duration. Defaults to DefaultSessionTTL.
	SessionTTL time.Duration
	// MaxSessionAge is the absolute maximum session lifetime. Defaults to DefaultMaxSessionAge.
	MaxSessionAge time.Duration
	// MaxSessions is the maximum concurrent sessions per account. Defaults to DefaultMaxSessions.
	MaxSessions int
	// TokenRevoker for cascading token revocation. Optional.
	TokenRevoker TokenRevoker
	// IndexFailClosed controls behavior when Redis index operations fail in CreateSession.
	// false (default) = log warning and continue (fail-open; sessions may become orphaned).
	// true            = return error (fail-closed; may reject valid session creation).
	// Production deployments that prefer strict consistency should set this to true.
	IndexFailClosed bool
}

// cachedSession holds a parsed session, the raw JSON bytes for staleness
// detection, and the wall-clock time it was inserted into the local cache.
type cachedSession struct {
	session *domain.Session
	json    []byte
	cachedAt time.Time
}

// SessionService manages user sessions backed by Redis.
type SessionService struct {
	redis           *cache.RedisClient
	logger          *zap.Logger
	sessionTTL      time.Duration
	maxSessionAge   time.Duration
	maxSessions     int
	tokenRevoker    TokenRevoker
	indexFailClosed bool
	// sessionCache caches parsed sessions keyed by sessionID to avoid
	// repeated JSON unmarshal on the validation hot path.
	sessionCache sync.Map // map[string]cachedSession

	// cacheCleanupStop signals the background cleanup goroutine to exit.
	cacheCleanupStop chan struct{}
}

// NewSessionService creates a new session service instance with default configuration.
// Deprecated: Use NewSessionServiceWithConfig directly.
func NewSessionService(redis *cache.RedisClient, logger *zap.Logger) (*SessionService, error) {
	return NewSessionServiceWithConfig(redis, logger, SessionConfig{})
}

// NewSessionServiceWithConfig creates a new session service instance with the given config.
// Zero-valued fields use package defaults.
// Returns an error if redis is nil.
func NewSessionServiceWithConfig(redis *cache.RedisClient, logger *zap.Logger, cfg SessionConfig) (*SessionService, error) {
	if redis == nil {
		return nil, fmt.Errorf("NewSessionService: redis must not be nil")
	}
	logger = utility.EnsureLogger(logger)

	svc := &SessionService{
		redis:           redis,
		logger:          logger,
		sessionTTL:      DefaultSessionTTL,
		maxSessionAge:   DefaultMaxSessionAge,
		maxSessions:     DefaultMaxSessions,
		indexFailClosed: cfg.IndexFailClosed,
		cacheCleanupStop: make(chan struct{}),
	}
	if cfg.SessionTTL > 0 {
		svc.sessionTTL = cfg.SessionTTL
	}
	if cfg.MaxSessionAge > 0 {
		svc.maxSessionAge = cfg.MaxSessionAge
	}
	if cfg.MaxSessions > 0 {
		svc.maxSessions = cfg.MaxSessions
	}
	if cfg.TokenRevoker != nil {
		svc.tokenRevoker = cfg.TokenRevoker
	}

	go svc.startCacheCleanup()

	return svc, nil
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
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(session.ID)))
		return fmt.Errorf("marshal session: %w", err)
	}

	// Atomically store session and update account index via Lua script.
	// This prevents orphaned sessions if the process crashes between SET and SADD.
	sessionKey := s.buildSessionKey(session.ID)
	indexKey := s.buildAccountSessionsKey(session.AccountID)
	ttlSecs := int(math.Ceil(s.sessionTTL.Seconds()))
	if ttlSecs < 1 {
		ttlSecs = 1
	}
	if _, err := s.redis.RunScript(ctx, createSessionScript,
		[]string{sessionKey, indexKey}, string(data), ttlSecs, session.ID,
	).Result(); err != nil {
		s.logger.Error("Failed to create session (atomic)", zap.Error(err),
			zap.String("session_id", utility.MaskOpaqueID(session.ID)))
		return fmt.Errorf("create session: %w", err)
	}

	// Enforce maximum concurrent session limit
	if err := s.EnforceSessionLimit(ctx, session.AccountID); err != nil {
		if s.indexFailClosed {
			s.logger.Error("Failed to enforce session limit (fail-closed)",
				zap.Error(err), zap.String("account_id", utility.MaskOpaqueID(session.AccountID)))
			return fmt.Errorf("enforce session limit: %w", err)
		}
		s.logger.Warn("Failed to enforce session limit (fail-open)",
			zap.Error(err), zap.String("account_id", utility.MaskOpaqueID(session.AccountID)))
	}

	s.logger.Info("Session created",
		zap.String("session_id", utility.MaskOpaqueID(session.ID)),
		zap.String("account_id", utility.MaskOpaqueID(session.AccountID)),
		zap.String("ip", utility.MaskOpaqueID(session.IP)),
		zap.Duration("ttl", s.sessionTTL))

	// Pre-populate local cache to avoid re-fetching on the next validation.
	s.sessionCache.Store(session.ID, cachedSession{session: session, json: data, cachedAt: time.Now()})

	return nil
}

// GetSession retrieves session information from Redis.
//
// IMPORTANT: GetSession does NOT check whether the session has logically
// expired (i.e., whether LastActiveAt + sessionTTL has passed). Callers that
// require expiry validation must use ValidateSession instead, or call
// session.IsExpired(s.sessionTTL) on the returned session.
//
// This is intentional — methods like DeleteSession and RefreshSession need
// access to session metadata (e.g., AccountID) even when the session has
// logically expired, so they can perform cleanup operations.
func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	key := s.buildSessionKey(sessionID)
	data, err := s.redis.Get(ctx, key)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		s.logger.Error("Failed to get session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return nil, fmt.Errorf("get session: %w", err)
	}

	raw := []byte(data)

	// Return cached parsed session if the raw JSON has not changed.
	if cached, ok := s.sessionCache.Load(sessionID); ok {
		cs := cached.(cachedSession)
		if bytes.Equal(cs.json, raw) {
			return cs.session, nil
		}
	}

	var session domain.Session
	if err := json.Unmarshal(raw, &session); err != nil {
		s.logger.Error("Failed to unmarshal session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	s.sessionCache.Store(sessionID, cachedSession{session: &session, json: raw, cachedAt: time.Now()})

	return &session, nil
}

// UpdateSession updates session information atomically.
// Uses a Lua script to ensure the session still exists before overwriting,
// preventing resurrection of sessions that expired between the read and write.
func (s *SessionService) UpdateSession(ctx context.Context, session *domain.Session) error {
	session.UpdateActivity()

	// Serialize session data
	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(session.ID)))
		return fmt.Errorf("marshal session: %w", err)
	}

	// Atomically set only if the session still exists (prevents TOCTOU resurrection)
	key := s.buildSessionKey(session.ID)
	ok, err := s.redis.SetIfExists(ctx, key, data, s.sessionTTL)
	if err != nil {
		s.logger.Error("Failed to update session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(session.ID)))
		return fmt.Errorf("update session: %w", err)
	}
	if !ok {
		s.logger.Debug("Session expired during update, skipping", zap.String("session_id", utility.MaskOpaqueID(session.ID)))
		return fmt.Errorf("session %s no longer exists", utility.MaskOpaqueID(session.ID))
	}

	// Refresh the account sessions index TTL to prevent it from expiring before the session
	indexKey := s.buildAccountSessionsKey(session.AccountID)
	if err := s.redis.Expire(ctx, indexKey, s.sessionTTL); err != nil {
		s.logger.Warn("Failed to refresh account sessions index TTL", zap.String("account_id", utility.MaskOpaqueID(session.AccountID)), zap.Error(err))
	}

	// Invalidate cached entry so the next GetSession re-parses.
	s.sessionCache.Delete(session.ID)

	s.logger.Debug("Session updated", zap.String("session_id", utility.MaskOpaqueID(session.ID)))
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
		s.logger.Error("Failed to delete session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return fmt.Errorf("delete session: %w", err)
	}

	// Evict from local cache.
	s.sessionCache.Delete(sessionID)

	// Always attempt to clean up the account session index.
	// If the session was loaded, use its accountID. Otherwise, the stale
	// index entry will be cleaned up lazily by ListSessionsByAccount.
	if session != nil {
		indexKey := s.buildAccountSessionsKey(session.AccountID)
		if err := s.redis.SRem(ctx, indexKey, sessionID); err != nil {
			s.logger.Warn("Failed to remove session from account index",
				zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(err))
		}
	} else if getErr != nil {
		s.logger.Debug("Session data unavailable for index cleanup, stale entry will be cleaned by ListSessionsByAccount",
			zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(getErr))
	}

	s.logger.Info("Session deleted", zap.String("session_id", utility.MaskOpaqueID(sessionID)))
	return nil
}

// RefreshSession refreshes the session expiration.
func (s *SessionService) RefreshSession(ctx context.Context, sessionID string) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Reject refresh if session has exceeded absolute max lifetime
	if s.maxSessionAge > 0 && time.Since(session.CreatedAt) > s.maxSessionAge {
		s.expireSession(ctx, sessionID, s.buildAccountSessionsKey(session.AccountID))
		return ErrSessionExpired
	}

	session.UpdateActivity()

	data, err := json.Marshal(session)
	if err != nil {
		s.logger.Error("Failed to marshal session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return fmt.Errorf("marshal session: %w", err)
	}

	key := s.buildSessionKey(sessionID)
	ok, err := s.redis.SetIfExists(ctx, key, data, s.sessionTTL)
	if err != nil {
		s.logger.Error("Failed to refresh session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return fmt.Errorf("refresh session: %w", err)
	}
	if !ok {
		return fmt.Errorf("session %s no longer exists", utility.MaskOpaqueID(sessionID))
	}

	// Refresh the account sessions index TTL to prevent it from expiring before the session
	indexKey := s.buildAccountSessionsKey(session.AccountID)
	if err := s.redis.Expire(ctx, indexKey, s.sessionTTL); err != nil {
		s.logger.Warn("Failed to refresh account sessions index TTL",
			zap.String("account_id", utility.MaskOpaqueID(session.AccountID)), zap.Error(err))
	}

	// Invalidate cached entry so the next GetSession re-parses with updated LastActiveAt.
	s.sessionCache.Delete(sessionID)

	return nil
}

// ValidateSession validates whether a session is still active.
func (s *SessionService) ValidateSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	// Use GETEX to atomically retrieve and refresh TTL, saving one round-trip
	// compared to the previous GET + EXPIRE sequence.
	key := s.buildSessionKey(sessionID)
	data, err := s.redis.GetEx(ctx, key, s.sessionTTL)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		s.logger.Error("Failed to get session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return nil, fmt.Errorf("get session: %w", err)
	}

	raw := []byte(data)

	// Return cached parsed session if the raw JSON has not changed.
	var session *domain.Session
	if cached, ok := s.sessionCache.Load(sessionID); ok {
		cs := cached.(cachedSession)
		if bytes.Equal(cs.json, raw) {
			session = cs.session
		}
	}
	if session == nil {
		var parsed domain.Session
		if err := json.Unmarshal(raw, &parsed); err != nil {
			s.logger.Error("Failed to unmarshal session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
			return nil, fmt.Errorf("unmarshal session: %w", err)
		}
		session = &parsed
		s.sessionCache.Store(sessionID, cachedSession{session: session, json: raw, cachedAt: time.Now()})
	}

	// Check absolute max session lifetime (prevents indefinite session extension)
	if s.maxSessionAge > 0 && time.Since(session.CreatedAt) > s.maxSessionAge {
		s.logger.Warn("Session exceeded max lifetime",
			zap.String("session_id", utility.MaskOpaqueID(sessionID)),
			zap.Duration("max_age", s.maxSessionAge))
		s.expireSession(ctx, sessionID, s.buildAccountSessionsKey(session.AccountID))
		return nil, ErrSessionExpired
	}

	// Check if session has expired due to inactivity
	if session.IsExpired(s.sessionTTL) {
		s.logger.Warn("Session expired", zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		s.expireSession(ctx, sessionID, s.buildAccountSessionsKey(session.AccountID))
		return nil, ErrSessionExpired
	}

	return session, nil
}

// expireSession cascades token revocation and deletes the session.
// Uses a Lua script to atomically verify the session is still expired before
// deleting, preventing a concurrent RefreshSession from being invalidated.
// The accountSessionsKey parameter (may be empty) enables cleanup of stale
// entries from the account_sessions index set.
func (s *SessionService) expireSession(ctx context.Context, sessionID string, accountSessionsKey string) {
	sessionKey := s.buildSessionKey(sessionID)
	result, err := s.redis.RunScript(ctx, deleteIfExpiredScript,
		[]string{sessionKey, accountSessionsKey}, sessionID).Int()
	if err != nil {
		s.logger.Warn("Failed to atomically check and delete expired session",
			zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(err))
		// Fallback to non-atomic delete.
		// NOTE: There is a small race window — if a concurrent RefreshSession
		// re-creates this session key between the failed Lua script and this
		// DEL, the newly-refreshed session will be incorrectly deleted. This
		// is acceptable as a rare edge case since the Lua script failure itself
		// is uncommon and the TTL-based refresh window is short.
		if delErr := s.redis.Del(ctx, sessionKey); delErr != nil {
			s.logger.Warn("Failed to delete expired session (fallback)",
				zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(delErr))
		}
		if accountSessionsKey != "" {
			if remErr := s.redis.SRem(ctx, accountSessionsKey, sessionID); remErr != nil {
				s.logger.Warn("Failed to remove stale session index entry (fallback)",
					zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(remErr))
			}
		}
		// Revoke tokens in fallback path — session was deleted (best-effort).
		if s.tokenRevoker != nil {
			if revokeErr := s.tokenRevoker.RevokeAllForSession(ctx, sessionID); revokeErr != nil {
				s.logger.Warn("Failed to revoke tokens for expired session (fallback)",
					zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(revokeErr))
			}
		}
		return
	} else if result == 0 {
		s.logger.Info("Session was refreshed concurrently, skipping expiry",
			zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		return
	}

	// Session was atomically confirmed expired and deleted — safe to revoke tokens.
	// Token revocation is done AFTER the atomic check to prevent revoking tokens
	// for a session that was concurrently refreshed by RefreshSession.
	if s.tokenRevoker != nil {
		if err := s.tokenRevoker.RevokeAllForSession(ctx, sessionID); err != nil {
			s.logger.Warn("Failed to revoke tokens for expired session",
				zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(err))
		}
	}
}

// buildSessionKey builds the Redis key for a session.
func (s *SessionService) buildSessionKey(sessionID string) string {
	return sessionKeyPrefix + sessionID
}

// buildAccountSessionsKey builds the Redis key for the account session index.
func (s *SessionService) buildAccountSessionsKey(accountID string) string {
	return accountSessionsPrefix + accountID
}

// startCacheCleanup runs a background goroutine that periodically evicts stale
// entries from the local sessionCache.  An entry is considered stale if it was
// inserted more than 2 * sessionTTL ago — the generous multiplier accounts for
// the worst-case scenario where the entry was cached just before the Redis TTL
// was refreshed, so 2 * TTL guarantees the Redis key has long since expired.
//
// The sweep interval is the lesser of sessionTTL and maxCacheCleanupInterval
// (1h), ensuring stale entries are cleaned up promptly even when sessionTTL is
// very high (e.g., 24h).
func (s *SessionService) startCacheCleanup() {
	cleanupInterval := s.sessionTTL
	if cleanupInterval > maxCacheCleanupInterval {
		cleanupInterval = maxCacheCleanupInterval
	}
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.evictStaleCacheEntries()
		case <-s.cacheCleanupStop:
			return
		}
	}
}

// evictStaleCacheEntries removes entries from the local sessionCache whose
// cachedAt timestamp is older than 2 × sessionTTL.
func (s *SessionService) evictStaleCacheEntries() {
	threshold := time.Now().Add(-2 * s.sessionTTL)
	var evicted int
	s.sessionCache.Range(func(key, value any) bool {
		cs := value.(cachedSession)
		if cs.cachedAt.Before(threshold) {
			s.sessionCache.Delete(key)
			evicted++
		}
		return true
	})
	if evicted > 0 {
		s.logger.Debug("Evicted stale session cache entries",
			zap.Int("count", evicted),
			zap.Duration("threshold", 2*s.sessionTTL))
	}
}

// StopCacheCleanup stops the background cache-cleanup goroutine.
// Call this during graceful shutdown to avoid goroutine leaks.
func (s *SessionService) StopCacheCleanup() {
	select {
	case <-s.cacheCleanupStop:
		// already closed
	default:
		close(s.cacheCleanupStop)
	}
}

// Error definitions
var (
	ErrSessionNotFound           = errors.New("session not found")
	ErrSessionExpired            = errors.New("session expired")
	ErrSessionAccessDenied       = errors.New("session not found or access denied")
	ErrTokenRevokerNotConfigured = errors.New("token revoker not configured")
)
