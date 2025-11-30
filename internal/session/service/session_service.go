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
	// DefaultSessionTTL 默认会话过期时间（24小时）
	DefaultSessionTTL = 24 * time.Hour
)

// SessionService 会话管理服务
type SessionService struct {
	redis     *cache.RedisClient
	logger    *zap.Logger
	sessionTTL time.Duration
}

// NewSessionService 创建会话服务实例
func NewSessionService(redis *cache.RedisClient, logger *zap.Logger) *SessionService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &SessionService{
		redis:     redis,
		logger:    logger,
		sessionTTL: DefaultSessionTTL,
	}
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

// 错误定义
var (
	ErrSessionNotFound = fmt.Errorf("session not found")
	ErrSessionExpired  = fmt.Errorf("session expired")
)
