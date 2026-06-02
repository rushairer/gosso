package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// 注意：这些测试需要 Redis 服务运行
// 可以通过 docker-compose 启动测试环境

func setupTestRedisClient(t *testing.T) *RedisClient {
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15" // 使用 DB 15 用于测试

	client, err := NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	return client
}

func TestRedisClient_SetGet(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:key"
	value := "test_value"

	// 测试 Set
	err := client.Set(ctx, key, value, 10*time.Second)
	require.NoError(t, err)

	// 测试 Get
	result, err := client.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value, result)

	// 清理
	_ = client.Del(ctx, key)
}

func TestRedisClient_KeyNotFound(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:nonexistent"

	_, err := client.Get(ctx, key)
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestRedisClient_Expiration(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:expire"
	value := "expire_value"

	// 设置短过期时间
	err := client.Set(ctx, key, value, 1*time.Second)
	require.NoError(t, err)

	// 立即读取应该成功
	result, err := client.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value, result)

	// 等待过期
	time.Sleep(2 * time.Second)

	// 应该已过期
	_, err = client.Get(ctx, key)
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestRedisClient_Incr(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:counter"

	// 第一次递增
	val1, err := client.Incr(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, int64(1), val1)

	// 第二次递增
	val2, err := client.Incr(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, int64(2), val2)

	// 清理
	_ = client.Del(ctx, key)
}

func TestRedisClient_Hash(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:hash"

	// 设置哈希字段
	err := client.HSet(ctx, key, "field1", "value1", "field2", "value2")
	require.NoError(t, err)

	// 获取单个字段
	val, err := client.HGet(ctx, key, "field1")
	require.NoError(t, err)
	assert.Equal(t, "value1", val)

	// 获取所有字段
	allFields, err := client.HGetAll(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, 2, len(allFields))
	assert.Equal(t, "value1", allFields["field1"])
	assert.Equal(t, "value2", allFields["field2"])

	// 清理
	_ = client.Del(ctx, key)
}

func TestRedisClient_Set(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:set"

	// 添加集合成员
	err := client.SAdd(ctx, key, "member1", "member2", "member3")
	require.NoError(t, err)

	// 检查成员是否存在
	exists, err := client.SIsMember(ctx, key, "member1")
	require.NoError(t, err)
	assert.True(t, exists)

	// 获取所有成员
	members, err := client.SMembers(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, 3, len(members))

	// 清理
	_ = client.Del(ctx, key)
}
