package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/session/domain"
	"go.uber.org/zap"
)

const (
	// SessionKeyPrefix Redis 会话键前缀
	SessionKeyPrefix = "session:"
	// AccountSessionsPrefix 账号会话索引键前缀
	AccountSessionsPrefix = "account_sessions:"
	// DefaultSessionTTL 默认会话过期时间（24小时）
	DefaultSessionTTL = 24 * time.Hour
	// DefaultMaxSessions 默认最大并发会话数
	DefaultMaxSessions = 10
)

// SessionService 会话管理服务
type SessionService struct {
	redis      *cache.RedisClient
	logger     *zap.Logger
	sessionTTL time.Duration
	maxSessions int
}

// NewSessionService 创建会话服务实例
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

// SetMaxSessions 设置最大并发会话数
func (s *SessionService) SetMaxSessions(n int) {
	s.maxSessions = n
}

// SetSessionTTL 设置会话过期时间
func (s *SessionService) SetSessionTTL(ttl time.Duration) {
	s.sessionTTL = ttl
}

// CreateSession 创建新会话
func (s *SessionService) CreateSession(ctx context.Context, session *domain.Session) error {
	if session.ID == uuid.Nil {
		session.ID = uuid.New()
	}

	now := time.Now()
	session.CreatedAt = now
	session.LastActiveAt = now

	// 序列化会话数据
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

	// 维护账号会话索引
	indexKey := s.buildAccountSessionsKey(session.AccountID.String())
	if err := s.redis.SAdd(ctx, indexKey, session.ID.String()); err != nil {
		s.logger.Warn("Failed to index session by account", zap.Error(err), zap.String("session_id", session.ID.String()))
	}

	s.logger.Info("Session created",
		zap.String("session_id", session.ID.String()),
		zap.String("account_id", session.AccountID.String()),
		zap.Duration("ttl", s.sessionTTL))

	return nil
}

// GetSession 获取会话信息
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

// UpdateSession 更新会话信息
func (s *SessionService) UpdateSession(ctx context.Context, session *domain.Session) error {
	// 先检查会话是否存在
	if _, err := s.GetSession(ctx, session.ID); err != nil {
		return err
	}

	session.UpdateActivity()

	// 序列化会话数据
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

// DeleteSession 删除会话
func (s *SessionService) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	key := s.buildSessionKey(sessionID)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to delete session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return fmt.Errorf("delete session: %w", err)
	}

	s.logger.Info("Session deleted", zap.String("session_id", sessionID.String()))
	return nil
}

// RefreshSession 刷新会话过期时间
func (s *SessionService) RefreshSession(ctx context.Context, sessionID uuid.UUID) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	session.UpdateActivity()
	return s.UpdateSession(ctx, session)
}

// ValidateSession 验证会话是否有效
func (s *SessionService) ValidateSession(ctx context.Context, sessionID uuid.UUID) (*domain.Session, error) {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// 检查会话是否过期
	if session.IsExpired(s.sessionTTL) {
		s.logger.Warn("Session expired", zap.String("session_id", sessionID.String()))
		// 删除过期会话
		_ = s.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}

	return session, nil
}

// buildSessionKey 构建 Redis 键
func (s *SessionService) buildSessionKey(sessionID uuid.UUID) string {
	return fmt.Sprintf("%s%s", SessionKeyPrefix, sessionID.String())
}

// buildAccountSessionsKey 构建账号会话索引键
func (s *SessionService) buildAccountSessionsKey(accountID string) string {
	return fmt.Sprintf("%s%s", AccountSessionsPrefix, accountID)
}

// RevokeAllForAccount 撤销指定账号的所有会话
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

	// 删除索引本身
	if err := s.redis.Del(ctx, indexKey); err != nil {
		s.logger.Warn("Failed to delete account sessions index", zap.String("account_id", accountID), zap.Error(err))
	}

	s.logger.Info("All sessions revoked for account",
		zap.String("account_id", accountID),
		zap.Int("count", len(sessionIDs)))

	return nil
}

// ListSessionsByAccount 列出账号的所有活跃会话
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
			// 会话已过期或不存在，从索引中移除
			_ = s.redis.SRem(ctx, indexKey, sid)
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// RevokeSession 撤销指定会话（ownership check）
func (s *SessionService) RevokeSession(ctx context.Context, accountID string, sessionID uuid.UUID) error {
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.AccountID.String() != accountID {
		return fmt.Errorf("session does not belong to account")
	}

	// 从索引中移除
	indexKey := s.buildAccountSessionsKey(accountID)
	_ = s.redis.SRem(ctx, indexKey, sessionID.String())

	return s.DeleteSession(ctx, sessionID)
}

// EnforceSessionLimit 检查并强制执行最大并发会话数限制
// 当超出限制时，删除最旧的会话
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

	// 按 LastActiveAt 排序，删除最旧的
	// 简单冒泡排序（会话数通常很少）
	for i := 0; i < len(sessions)-1; i++ {
		for j := i + 1; j < len(sessions); j++ {
			if sessions[i].LastActiveAt.After(sessions[j].LastActiveAt) {
				sessions[i], sessions[j] = sessions[j], sessions[i]
			}
		}
	}

	// 删除多余的旧会话
	toRemove := len(sessions) - s.maxSessions
	for i := 0; i < toRemove; i++ {
		s.logger.Info("Revoking old session due to limit",
			zap.String("session_id", sessions[i].ID.String()),
			zap.String("account_id", accountID))
		_ = s.RevokeSession(ctx, accountID, sessions[i].ID)
	}
}

// 错误定义
var (
	ErrSessionNotFound = fmt.Errorf("session not found")
	ErrSessionExpired  = fmt.Errorf("session expired")
)
