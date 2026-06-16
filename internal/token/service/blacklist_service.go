package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	// BlacklistKeyPrefix is the Redis key prefix for token blacklist
	BlacklistKeyPrefix = "blacklist:token:"
	// AccountRevokedAfterPrefix is the Redis key prefix for account-level token revocation.
	// Stores the unix timestamp after which all access tokens for the account are considered revoked.
	AccountRevokedAfterPrefix = "account_revoked_after:"
)

// BlacklistService handles token blacklist operations
type BlacklistService struct {
	redis  *cache.RedisClient
	logger *zap.Logger
}

// NewBlacklistService creates a new token blacklist service instance.
// Returns an error if redis is nil.
func NewBlacklistService(redis *cache.RedisClient, logger *zap.Logger) (*BlacklistService, error) {
	if redis == nil {
		return nil, errors.New("blacklist service: redis client is required")
	}
	logger = utility.EnsureLogger(logger)

	return &BlacklistService{
		redis:  redis,
		logger: logger,
	}, nil
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

	// Calculate TTL: time from now until token expiration, with a 5-minute buffer
	// to account for clock skew between Redis and JWT validation.
	ttl := time.Until(expiresAt) + 5*time.Minute
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
	if errors.Is(err, cache.ErrKeyNotFound) {
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

// removeFromBlacklist is used only in tests to reset state between test runs.
func (s *BlacklistService) removeFromBlacklist(ctx context.Context, jti string) error {
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

// setAccountRevokedAfterScript atomically updates the revoked-after timestamp only if the
// new value is greater than the existing one. This prevents concurrent revocation requests
// from "un-revoking" tokens by overwriting a later timestamp with an earlier one.
// KEYS[1] = account_revoked_after:{accountID}
// ARGV[1] = new timestamp (Unix seconds)
// ARGV[2] = TTL in seconds
// Returns 1 if updated, 0 if existing value is already >= new value.
var setAccountRevokedAfterScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur and tonumber(ARGV[1]) <= tonumber(cur) then
    return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1
`)

// SetAccountRevokedAfter records that all access tokens issued before the given
// timestamp should be considered revoked for the given account. The key
// automatically expires after the specified duration (should be >= access token
// expiry to ensure all pre-revocation tokens have naturally expired).
// Uses a ratchet: only updates if the new timestamp is greater than the existing one.
func (s *BlacklistService) SetAccountRevokedAfter(ctx context.Context, accountID string, revokedAt time.Time, ttl time.Duration) error {
	key := s.buildAccountRevokedAfterKey(accountID)
	timestamp := revokedAt.Unix()

	result, err := s.redis.RunScript(ctx, setAccountRevokedAfterScript, []string{key},
		timestamp, int(ttl.Seconds()),
	).Int64()
	if err != nil {
		s.logger.Error("Failed to set account revoked-after timestamp",
			zap.String("account_id", accountID), zap.Error(err))
		return fmt.Errorf("set account revoked after: %w", err)
	}

	if result == 0 {
		s.logger.Debug("Account revoked-after timestamp already set to a later value, skipping",
			zap.String("account_id", accountID),
			zap.Time("revoked_at", revokedAt))
		return nil
	}

	s.logger.Info("Account tokens revoked after timestamp",
		zap.String("account_id", accountID),
		zap.Time("revoked_at", revokedAt),
		zap.Duration("ttl", ttl))

	return nil
}

// GetAccountRevokedAfter returns the timestamp after which all access tokens
// for the given account should be considered revoked.
// Returns (time.Time{}, nil) if no revocation record exists.
func (s *BlacklistService) GetAccountRevokedAfter(ctx context.Context, accountID string) (time.Time, error) {
	key := s.buildAccountRevokedAfterKey(accountID)
	val, err := s.redis.Get(ctx, key)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return time.Time{}, nil
	}
	if err != nil {
		s.logger.Error("Failed to get account revoked-after timestamp",
			zap.String("account_id", accountID), zap.Error(err))
		return time.Time{}, fmt.Errorf("get account revoked after: %w", err)
	}

	unixTimestamp, parseErr := strconv.ParseInt(val, 10, 64)
	if parseErr != nil {
		s.logger.Error("Failed to parse account revoked-after timestamp",
			zap.String("account_id", accountID), zap.String("value", val), zap.Error(parseErr))
		return time.Time{}, fmt.Errorf("parse account revoked after: %w", parseErr)
	}

	return time.Unix(unixTimestamp, 0), nil
}

// buildAccountRevokedAfterKey constructs the Redis key for account-level revocation.
func (s *BlacklistService) buildAccountRevokedAfterKey(accountID string) string {
	return fmt.Sprintf("%s%s", AccountRevokedAfterPrefix, accountID)
}

// Error definitions
var (
	ErrTokenNotRevoked = errors.New("token not revoked")
)
