package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
)

const (
	// BlacklistKeyPrefix Redis Token 黑名单键前缀
	BlacklistKeyPrefix = "blacklist:token:"
)

// BlacklistService Token 黑名单服务
type BlacklistService struct {
	redis  *cache.RedisClient
	logger *zap.Logger
}

// NewBlacklistService 创建 Token 黑名单服务实例
func NewBlacklistService(redis *cache.RedisClient, logger *zap.Logger) *BlacklistService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &BlacklistService{
		redis:  redis,
		logger: logger,
	}
}

// RevokeToken 撤销 Token（加入黑名单）
func (s *BlacklistService) RevokeToken(ctx context.Context, jti string, reason string, expiresAt time.Time) error {
	blacklist := &domain.TokenBlacklist{
		JTI:       jti,
		Reason:    reason,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	data, err := json.Marshal(blacklist)
	if err != nil {
		s.logger.Error("Failed to marshal token blacklist", zap.Error(err), zap.String("jti", jti))
		return fmt.Errorf("marshal token blacklist: %w", err)
	}

	// 计算 TTL：从现在到 Token 过期的时间
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token 已经过期，不需要加入黑名单
		s.logger.Warn("Token already expired, skip blacklist", zap.String("jti", jti))
		return nil
	}

	key := s.buildBlacklistKey(jti)
	if err := s.redis.Set(ctx, key, data, ttl); err != nil {
		s.logger.Error("Failed to revoke token", zap.Error(err), zap.String("jti", jti))
		return fmt.Errorf("revoke token: %w", err)
	}

	s.logger.Info("Token revoked",
		zap.String("jti", jti),
		zap.String("reason", reason),
		zap.Duration("ttl", ttl))

	return nil
}

// IsTokenRevoked 检查 Token 是否已被撤销
func (s *BlacklistService) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	key := s.buildBlacklistKey(jti)
	exists, err := s.redis.Exists(ctx, key)
	if err != nil {
		s.logger.Error("Failed to check token blacklist", zap.Error(err), zap.String("jti", jti))
		return false, fmt.Errorf("check token blacklist: %w", err)
	}

	return exists, nil
}

// GetRevokeInfo 获取 Token 撤销信息
func (s *BlacklistService) GetRevokeInfo(ctx context.Context, jti string) (*domain.TokenBlacklist, error) {
	key := s.buildBlacklistKey(jti)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
		return nil, ErrTokenNotRevoked
	}
	if err != nil {
		s.logger.Error("Failed to get token blacklist", zap.Error(err), zap.String("jti", jti))
		return nil, fmt.Errorf("get token blacklist: %w", err)
	}

	var blacklist domain.TokenBlacklist
	if err := json.Unmarshal([]byte(data), &blacklist); err != nil {
		s.logger.Error("Failed to unmarshal token blacklist", zap.Error(err), zap.String("jti", jti))
		return nil, fmt.Errorf("unmarshal token blacklist: %w", err)
	}

	return &blacklist, nil
}

// RemoveFromBlacklist 从黑名单中移除 Token（慎用，通常仅用于测试或特殊场景）
func (s *BlacklistService) RemoveFromBlacklist(ctx context.Context, jti string) error {
	key := s.buildBlacklistKey(jti)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to remove token from blacklist", zap.Error(err), zap.String("jti", jti))
		return fmt.Errorf("remove token from blacklist: %w", err)
	}

	s.logger.Info("Token removed from blacklist", zap.String("jti", jti))
	return nil
}

// buildBlacklistKey 构建 Redis 键
func (s *BlacklistService) buildBlacklistKey(jti string) string {
	return fmt.Sprintf("%s%s", BlacklistKeyPrefix, jti)
}

// 错误定义
var (
	ErrTokenNotRevoked = fmt.Errorf("token not revoked")
)
