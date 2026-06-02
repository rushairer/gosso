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
	// BlacklistKeyPrefix is the Redis key prefix for token blacklist
	BlacklistKeyPrefix = "blacklist:token:"
)

// BlacklistService handles token blacklist operations
type BlacklistService struct {
	redis  *cache.RedisClient
	logger *zap.Logger
}

// NewBlacklistService creates a new token blacklist service instance
func NewBlacklistService(redis *cache.RedisClient, logger *zap.Logger) *BlacklistService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &BlacklistService{
		redis:  redis,
		logger: logger,
	}
}

// RevokeToken revokes a token (adds it to the blacklist)
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

	// Calculate TTL: time from now until token expiration
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token has already expired, no need to add to blacklist
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

// IsTokenRevoked checks whether a token has been revoked
func (s *BlacklistService) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	key := s.buildBlacklistKey(jti)
	exists, err := s.redis.Exists(ctx, key)
	if err != nil {
		s.logger.Error("Failed to check token blacklist", zap.Error(err), zap.String("jti", jti))
		return false, fmt.Errorf("check token blacklist: %w", err)
	}

	return exists, nil
}

// GetRevokeInfo retrieves the revocation information for a token
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

// RemoveFromBlacklist removes a token from the blacklist (use with caution, typically for testing or special scenarios only)
func (s *BlacklistService) RemoveFromBlacklist(ctx context.Context, jti string) error {
	key := s.buildBlacklistKey(jti)
	if err := s.redis.Del(ctx, key); err != nil {
		s.logger.Error("Failed to remove token from blacklist", zap.Error(err), zap.String("jti", jti))
		return fmt.Errorf("remove token from blacklist: %w", err)
	}

	s.logger.Info("Token removed from blacklist", zap.String("jti", jti))
	return nil
}

// buildBlacklistKey constructs the Redis key
func (s *BlacklistService) buildBlacklistKey(jti string) string {
	return fmt.Sprintf("%s%s", BlacklistKeyPrefix, jti)
}

// Error definitions
var (
	ErrTokenNotRevoked = fmt.Errorf("token not revoked")
)
