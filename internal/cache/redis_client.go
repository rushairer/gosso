package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RedisClient 封装 Redis 客户端，提供统一的缓存操作接口
type RedisClient struct {
	client *redis.Client
	logger *zap.Logger
}

// NewRedisClient 创建 Redis 客户端实例
// dsn 格式: redis://[user:password@]host:port/db
// 示例: redis://:password@localhost:6379/0
func NewRedisClient(dsn string, maxActiveConns int, poolTimeout time.Duration, logger *zap.Logger) (*RedisClient, error) {
	opts, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse redis DSN: %w", err)
	}

	// 配置连接池参数
	opts.PoolSize = maxActiveConns
	opts.PoolTimeout = poolTimeout
	opts.MaxRetries = 3
	opts.MinRetryBackoff = 100 * time.Millisecond
	opts.MaxRetryBackoff = 500 * time.Millisecond

	client := redis.NewClient(opts)

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Info("Redis client initialized",
		zap.String("addr", opts.Addr),
		zap.Int("pool_size", opts.PoolSize),
		zap.Duration("pool_timeout", opts.PoolTimeout))

	return &RedisClient{
		client: client,
		logger: logger,
	}, nil
}

// Close 关闭 Redis 连接
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Ping 测试连接
func (r *RedisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Set 设置键值（带过期时间）
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	err := r.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		r.logger.Error("Redis SET failed", zap.String("key", key), zap.Error(err))
		return fmt.Errorf("set key %s: %w", key, err)
	}
	return nil
}

// Get 获取键值
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", ErrKeyNotFound
	}
	if err != nil {
		r.logger.Error("Redis GET failed", zap.String("key", key), zap.Error(err))
		return "", fmt.Errorf("get key %s: %w", key, err)
	}
	return val, nil
}

// Del 删除键
func (r *RedisClient) Del(ctx context.Context, keys ...string) error {
	err := r.client.Del(ctx, keys...).Err()
	if err != nil {
		r.logger.Error("Redis DEL failed", zap.Strings("keys", keys), zap.Error(err))
		return fmt.Errorf("delete keys: %w", err)
	}
	return nil
}

// Exists 检查键是否存在
func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	count, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis EXISTS failed", zap.String("key", key), zap.Error(err))
		return false, fmt.Errorf("check key %s: %w", key, err)
	}
	return count > 0, nil
}

// Expire 设置键的过期时间
func (r *RedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	err := r.client.Expire(ctx, key, expiration).Err()
	if err != nil {
		r.logger.Error("Redis EXPIRE failed", zap.String("key", key), zap.Error(err))
		return fmt.Errorf("expire key %s: %w", key, err)
	}
	return nil
}

// Incr 递增计数器
func (r *RedisClient) Incr(ctx context.Context, key string) (int64, error) {
	val, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis INCR failed", zap.String("key", key), zap.Error(err))
		return 0, fmt.Errorf("incr key %s: %w", key, err)
	}
	return val, nil
}

// Decr 递减计数器
func (r *RedisClient) Decr(ctx context.Context, key string) (int64, error) {
	val, err := r.client.Decr(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis DECR failed", zap.String("key", key), zap.Error(err))
		return 0, fmt.Errorf("decr key %s: %w", key, err)
	}
	return val, nil
}

// SetNX 仅在键不存在时设置（分布式锁）
func (r *RedisClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	ok, err := r.client.SetNX(ctx, key, value, expiration).Result()
	if err != nil {
		r.logger.Error("Redis SETNX failed", zap.String("key", key), zap.Error(err))
		return false, fmt.Errorf("setnx key %s: %w", key, err)
	}
	return ok, nil
}

// HSet 设置哈希字段
func (r *RedisClient) HSet(ctx context.Context, key string, values ...interface{}) error {
	err := r.client.HSet(ctx, key, values...).Err()
	if err != nil {
		r.logger.Error("Redis HSET failed", zap.String("key", key), zap.Error(err))
		return fmt.Errorf("hset key %s: %w", key, err)
	}
	return nil
}

// HGet 获取哈希字段
func (r *RedisClient) HGet(ctx context.Context, key, field string) (string, error) {
	val, err := r.client.HGet(ctx, key, field).Result()
	if err == redis.Nil {
		return "", ErrKeyNotFound
	}
	if err != nil {
		r.logger.Error("Redis HGET failed", zap.String("key", key), zap.String("field", field), zap.Error(err))
		return "", fmt.Errorf("hget key %s field %s: %w", key, field, err)
	}
	return val, nil
}

// HGetAll 获取哈希所有字段
func (r *RedisClient) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	val, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis HGETALL failed", zap.String("key", key), zap.Error(err))
		return nil, fmt.Errorf("hgetall key %s: %w", key, err)
	}
	return val, nil
}

// HDel 删除哈希字段
func (r *RedisClient) HDel(ctx context.Context, key string, fields ...string) error {
	err := r.client.HDel(ctx, key, fields...).Err()
	if err != nil {
		r.logger.Error("Redis HDEL failed", zap.String("key", key), zap.Strings("fields", fields), zap.Error(err))
		return fmt.Errorf("hdel key %s: %w", key, err)
	}
	return nil
}

// SAdd 添加集合成员
func (r *RedisClient) SAdd(ctx context.Context, key string, members ...interface{}) error {
	err := r.client.SAdd(ctx, key, members...).Err()
	if err != nil {
		r.logger.Error("Redis SADD failed", zap.String("key", key), zap.Error(err))
		return fmt.Errorf("sadd key %s: %w", key, err)
	}
	return nil
}

// SMembers 获取集合所有成员
func (r *RedisClient) SMembers(ctx context.Context, key string) ([]string, error) {
	val, err := r.client.SMembers(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis SMEMBERS failed", zap.String("key", key), zap.Error(err))
		return nil, fmt.Errorf("smembers key %s: %w", key, err)
	}
	return val, nil
}

// SIsMember 检查成员是否在集合中
func (r *RedisClient) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	ok, err := r.client.SIsMember(ctx, key, member).Result()
	if err != nil {
		r.logger.Error("Redis SISMEMBER failed", zap.String("key", key), zap.Error(err))
		return false, fmt.Errorf("sismember key %s: %w", key, err)
	}
	return ok, nil
}

// SRem 删除集合成员
func (r *RedisClient) SRem(ctx context.Context, key string, members ...interface{}) error {
	err := r.client.SRem(ctx, key, members...).Err()
	if err != nil {
		r.logger.Error("Redis SREM failed", zap.String("key", key), zap.Error(err))
		return fmt.Errorf("srem key %s: %w", key, err)
	}
	return nil
}

// TTL 获取键的剩余过期时间
func (r *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		r.logger.Error("Redis TTL failed", zap.String("key", key), zap.Error(err))
		return 0, fmt.Errorf("ttl key %s: %w", key, err)
	}
	return ttl, nil
}

// GetClient 获取底层 Redis 客户端（用于高级操作）
func (r *RedisClient) GetClient() *redis.Client {
	return r.client
}

// IncrWithExpiry 原子性递增计数器并设置过期时间（仅在 key 首次创建时）
// 避免 Incr + Expire 之间的竞态条件
func (r *RedisClient) IncrWithExpiry(ctx context.Context, key string, expiry time.Duration) (int64, error) {
	script := redis.NewScript(`
		local current = redis.call('INCR', KEYS[1])
		if current == 1 then
			redis.call('EXPIRE', KEYS[1], ARGV[1])
		end
		return current
	`)
	result, err := script.Run(ctx, r.client, []string{key}, int(expiry.Seconds())).Int64()
	if err != nil {
		r.logger.Error("Redis IncrWithExpiry failed", zap.String("key", key), zap.Error(err))
		return 0, fmt.Errorf("incrWithExpiry key %s: %w", key, err)
	}
	return result, nil
}

// ErrKeyNotFound Redis 键不存在错误
var ErrKeyNotFound = fmt.Errorf("redis: key not found")
