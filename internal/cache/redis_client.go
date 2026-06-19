package cache

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/utility"
)

// RedisClient wraps the Redis client and provides a unified cache operation interface
type RedisClient struct {
	client *redis.Client
	logger *zap.Logger
}

// NewRedisClient creates a new Redis client instance.
// DSN format: redis://[user:password@]host:port/db
// Example: redis://:password@localhost:6379/0
// The ctx parameter controls the ping timeout; pass context.Background() for startup.
func NewRedisClient(ctx context.Context, dsn string, maxActiveConns int, poolTimeout, dialTimeout, readTimeout, writeTimeout time.Duration, logger *zap.Logger) (*RedisClient, error) {
	opts, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse redis DSN: %w", err)
	}

	// Configure connection pool parameters
	opts.PoolSize = maxActiveConns
	opts.PoolTimeout = poolTimeout
	opts.MaxRetries = 3
	opts.MinRetryBackoff = 100 * time.Millisecond
	opts.MaxRetryBackoff = 500 * time.Millisecond
	opts.DialTimeout = dialTimeout
	opts.ReadTimeout = readTimeout
	opts.WriteTimeout = writeTimeout

	client := redis.NewClient(opts)

	// Test connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	logger = utility.EnsureLogger(logger)

	// Mask password in address for logging
	safeAddr := opts.Addr
	if atIndex := strings.LastIndex(safeAddr, "@"); atIndex != -1 {
		if colonIndex := strings.LastIndex(safeAddr[:atIndex], ":"); colonIndex != -1 && colonIndex > strings.LastIndex(safeAddr[:atIndex], "/") {
			safeAddr = safeAddr[:colonIndex+1] + "***" + safeAddr[atIndex:]
		}
	}

	logger.Info("Redis client initialized",
		zap.String("addr", safeAddr),
		zap.Int("pool_size", opts.PoolSize),
		zap.Duration("pool_timeout", opts.PoolTimeout))

	return &RedisClient{
		client: client,
		logger: logger,
	}, nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Ping tests the connection
func (r *RedisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Set sets a key-value pair (with expiration)
func (r *RedisClient) Set(ctx context.Context, key string, value any, expiration time.Duration) error {
	err := r.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		r.logger.Error("Redis SET failed", zap.String("key", maskKey(key)), zap.Error(err))
		return fmt.Errorf("set: %w", err)
	}
	return nil
}

// Get gets a key's value
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	if err != nil {
		r.logger.Error("Redis GET failed", zap.String("key", maskKey(key)), zap.Error(err))
		return "", fmt.Errorf("get: %w", err)
	}
	return val, nil
}

// Del deletes keys
func (r *RedisClient) Del(ctx context.Context, keys ...string) error {
	err := r.client.Del(ctx, keys...).Err()
	if err != nil {
		r.logger.Error("Redis DEL failed", zap.Strings("keys", maskKeys(keys)), zap.Error(err))
		return fmt.Errorf("delete keys: %w", err)
	}
	return nil
}

// Exists checks if a key exists
func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	count, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis EXISTS failed", zap.String("key", maskKey(key)), zap.Error(err))
		return false, fmt.Errorf("exists: %w", err)
	}
	return count > 0, nil
}

// Expire sets the expiration time for a key
func (r *RedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	err := r.client.Expire(ctx, key, expiration).Err()
	if err != nil {
		r.logger.Error("Redis EXPIRE failed", zap.String("key", maskKey(key)), zap.Error(err))
		return fmt.Errorf("expire: %w", err)
	}
	return nil
}

// Incr increments a counter
func (r *RedisClient) Incr(ctx context.Context, key string) (int64, error) {
	val, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis INCR failed", zap.String("key", maskKey(key)), zap.Error(err))
		return 0, fmt.Errorf("incr: %w", err)
	}
	return val, nil
}

// Decr decrements a counter
func (r *RedisClient) Decr(ctx context.Context, key string) (int64, error) {
	val, err := r.client.Decr(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis DECR failed", zap.String("key", maskKey(key)), zap.Error(err))
		return 0, fmt.Errorf("decr: %w", err)
	}
	return val, nil
}

// SetNX sets a key only if it does not exist (distributed lock)
func (r *RedisClient) SetNX(ctx context.Context, key string, value any, expiration time.Duration) (bool, error) {
	ok, err := r.client.SetNX(ctx, key, value, expiration).Result()
	if err != nil {
		r.logger.Error("Redis SETNX failed", zap.String("key", maskKey(key)), zap.Error(err))
		return false, fmt.Errorf("setnx: %w", err)
	}
	return ok, nil
}

// HSet sets hash fields
func (r *RedisClient) HSet(ctx context.Context, key string, values ...any) error {
	err := r.client.HSet(ctx, key, values...).Err()
	if err != nil {
		r.logger.Error("Redis HSET failed", zap.String("key", maskKey(key)), zap.Error(err))
		return fmt.Errorf("hset: %w", err)
	}
	return nil
}

// HGet gets a hash field
func (r *RedisClient) HGet(ctx context.Context, key, field string) (string, error) {
	val, err := r.client.HGet(ctx, key, field).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	if err != nil {
		r.logger.Error("Redis HGET failed", zap.String("key", maskKey(key)), zap.String("field", field), zap.Error(err))
		return "", fmt.Errorf("hget field %s: %w", field, err)
	}
	return val, nil
}

// HGetAll gets all hash fields
func (r *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	val, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis HGETALL failed", zap.String("key", maskKey(key)), zap.Error(err))
		return nil, fmt.Errorf("hgetall: %w", err)
	}
	return val, nil
}

// HDel deletes hash fields
func (r *RedisClient) HDel(ctx context.Context, key string, fields ...string) error {
	err := r.client.HDel(ctx, key, fields...).Err()
	if err != nil {
		r.logger.Error("Redis HDEL failed", zap.String("key", maskKey(key)), zap.Strings("fields", fields), zap.Error(err))
		return fmt.Errorf("hdel: %w", err)
	}
	return nil
}

// SAdd adds set members
func (r *RedisClient) SAdd(ctx context.Context, key string, members ...any) error {
	err := r.client.SAdd(ctx, key, members...).Err()
	if err != nil {
		r.logger.Error("Redis SADD failed", zap.String("key", maskKey(key)), zap.Error(err))
		return fmt.Errorf("sadd: %w", err)
	}
	return nil
}

// Package-level Lua scripts — redis.Script is safe for concurrent use and caches
// the script SHA after the first EVALSHA, avoiding repeated script body transmission.
var (
	saddWithTTLLuaScript = redis.NewScript(`redis.call('SADD', KEYS[1], ARGV[1]); return redis.call('EXPIRE', KEYS[1], ARGV[2])`)

	incrWithExpiryLuaScript = redis.NewScript(`
		local current = redis.call('INCR', KEYS[1])
		if current == 1 then
			redis.call('EXPIRE', KEYS[1], ARGV[1])
		end
		return current
	`)

	checkAndIncrLuaScript = redis.NewScript(`
		local current = tonumber(redis.call('GET', KEYS[1]) or '0')
		if current >= tonumber(ARGV[1]) then
			return current
		end
		local new = redis.call('INCR', KEYS[1])
		if new == 1 then
			redis.call('EXPIRE', KEYS[1], ARGV[2])
		end
		return new
	`)

	setIfExistsLuaScript = redis.NewScript(`
		if redis.call('EXISTS', KEYS[1]) == 1 then
			redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
			return 1
		end
		return 0
	`)
)

// SAddWithTTL atomically adds a member to a set and sets a TTL using a Lua script.
// The Lua script ensures SADD and EXPIRE execute atomically within Redis,
// eliminating any window for partial execution.
func (r *RedisClient) SAddWithTTL(ctx context.Context, key string, member string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("sadd_with_ttl: TTL must be positive, got %v", ttl)
	}
	secs := int(math.Ceil(ttl.Seconds()))
	if secs < 1 {
		secs = 1
	}
	_, err := saddWithTTLLuaScript.Run(ctx, r.client, []string{key}, member, secs).Result()
	if err != nil {
		r.logger.Error("Redis SADD+EXPIRE failed", zap.String("key", maskKey(key)), zap.Error(err))
		return fmt.Errorf("sadd_with_ttl: %w", err)
	}
	return nil
}

// SMembers gets all set members
func (r *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	val, err := r.client.SMembers(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis SMEMBERS failed", zap.String("key", maskKey(key)), zap.Error(err))
		return nil, fmt.Errorf("smembers: %w", err)
	}
	return val, nil
}

// SIsMember checks if a member is in the set
func (r *RedisClient) SIsMember(ctx context.Context, key string, member any) (bool, error) {
	ok, err := r.client.SIsMember(ctx, key, member).Result()
	if err != nil {
		r.logger.Error("Redis SISMEMBER failed", zap.String("key", maskKey(key)), zap.Error(err))
		return false, fmt.Errorf("sismember: %w", err)
	}
	return ok, nil
}

// SRem removes set members
func (r *RedisClient) SRem(ctx context.Context, key string, members ...any) error {
	err := r.client.SRem(ctx, key, members...).Err()
	if err != nil {
		r.logger.Error("Redis SREM failed", zap.String("key", maskKey(key)), zap.Error(err))
		return fmt.Errorf("srem: %w", err)
	}
	return nil
}

// TTL gets the remaining expiration time of a key
func (r *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis TTL failed", zap.String("key", maskKey(key)), zap.Error(err))
		return 0, fmt.Errorf("ttl: %w", err)
	}
	return ttl, nil
}

// GetClient returns the underlying Redis client (for advanced operations).
// Prefer RunScript for Lua script execution and other wrapper methods when possible.
func (r *RedisClient) GetClient() *redis.Client {
	return r.client
}

// RunScript executes a Redis Lua script, providing encapsulation for direct client access.
func (r *RedisClient) RunScript(ctx context.Context, script *redis.Script, keys []string, args ...any) *redis.Cmd {
	return script.Run(ctx, r.client, keys, args...)
}

// IncrWithExpiry atomically increments a counter and sets an expiration time (only on first creation)
// Avoids race conditions between Incr and Expire
func (r *RedisClient) IncrWithExpiry(ctx context.Context, key string, expiry time.Duration) (int64, error) {
	if expiry <= 0 {
		return 0, fmt.Errorf("incrWithExpiry: expiry must be positive, got %v", expiry)
	}
	result, err := incrWithExpiryLuaScript.Run(ctx, r.client, []string{key}, int(math.Ceil(expiry.Seconds()))).Int64()
	if err != nil {
		r.logger.Error("Redis IncrWithExpiry failed", zap.String("key", maskKey(key)), zap.Error(err))
		return 0, fmt.Errorf("incrWithExpiry: %w", err)
	}
	return result, nil
}

// CheckAndIncr atomically checks if a counter has reached the limit before incrementing.
// Returns the current count. If the count is already >= limit, the counter is NOT incremented.
// This prevents the counter from growing unboundedly past the limit.
func (r *RedisClient) CheckAndIncr(ctx context.Context, key string, limit int, expiry time.Duration) (int64, error) {
	if expiry <= 0 {
		return 0, fmt.Errorf("checkAndIncr: expiry must be positive, got %v", expiry)
	}
	result, err := checkAndIncrLuaScript.Run(ctx, r.client, []string{key}, limit, int(math.Ceil(expiry.Seconds()))).Int64()
	if err != nil {
		r.logger.Error("Redis CheckAndIncr failed", zap.String("key", maskKey(key)), zap.Error(err))
		return 0, fmt.Errorf("checkAndIncr: %w", err)
	}
	return result, nil
}

// SetIfExists atomically sets a key only if it already exists, preventing TOCTOU issues.
// Returns true if the key was updated, false if the key did not exist.
func (r *RedisClient) SetIfExists(ctx context.Context, key string, value any, expiry time.Duration) (bool, error) {
	expirySec := int(math.Ceil(expiry.Seconds()))
	if expirySec <= 0 {
		expirySec = 1 // Minimum 1 second to prevent persistent keys
	}
	result, err := setIfExistsLuaScript.Run(ctx, r.client, []string{key}, value, expirySec).Int64()
	if err != nil {
		r.logger.Error("Redis SetIfExists failed", zap.String("key", maskKey(key)), zap.Error(err))
		return false, fmt.Errorf("setIfExists: %w", err)
	}
	return result == 1, nil
}

// GetDel atomically retrieves and deletes a key in a single operation (Redis GETDEL).
// Returns ErrKeyNotFound if the key does not exist, consistent with Get behavior.
func (r *RedisClient) GetDel(ctx context.Context, key string) (string, error) {
	result, err := r.client.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	if err != nil {
		r.logger.Error("Redis GETDEL failed", zap.String("key", maskKey(key)), zap.Error(err))
		return "", fmt.Errorf("getDel: %w", err)
	}
	return result, nil
}

// maskKey redacts the last segment of a Redis key (after the last colon)
// to prevent PII such as email addresses or IP addresses from appearing in logs.
// Example: "verify:code:email:user@example.com" → "verify:code:email:***"
func maskKey(key string) string {
	if idx := strings.LastIndex(key, ":"); idx >= 0 {
		return key[:idx+1] + "***"
	}
	return "***"
}

// maskKeys applies maskKey to a slice of keys.
func maskKeys(keys []string) []string {
	masked := make([]string, len(keys))
	for i, k := range keys {
		masked[i] = maskKey(k)
	}
	return masked
}

// ErrKeyNotFound is the error returned when a Redis key does not exist
var ErrKeyNotFound = errors.New("redis: key not found")

// ScanKeys iterates over keys matching the given pattern using the SCAN command.
// Returns the matching keys and the next cursor position. When cursor returns 0, iteration is complete.
// The count parameter is a hint for how many keys to scan per iteration.
func (r *RedisClient) ScanKeys(ctx context.Context, cursor uint64, pattern string, count int64) ([]string, uint64, error) {
	keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, count).Result()
	if err != nil {
		r.logger.Error("Redis SCAN failed", zap.String("pattern_masked", maskKey(pattern)), zap.Error(err))
		return nil, 0, fmt.Errorf("scan pattern %s: %w", pattern, err)
	}
	return keys, nextCursor, nil
}
