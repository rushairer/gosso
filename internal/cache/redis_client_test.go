package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Note: these tests require a running Redis service
// You can start the test environment via docker-compose

func setupTestRedisClient(t *testing.T) *RedisClient {
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15" // Use DB 15 for testing

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

	// Test Set
	err := client.Set(ctx, key, value, 10*time.Second)
	require.NoError(t, err)

	// Test Get
	result, err := client.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value, result)

	// Cleanup
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

	// Set a short expiration time
	err := client.Set(ctx, key, value, 1*time.Second)
	require.NoError(t, err)

	// Reading immediately should succeed
	result, err := client.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value, result)

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Should have expired
	_, err = client.Get(ctx, key)
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestRedisClient_Incr(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:counter"

	// First increment
	val1, err := client.Incr(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, int64(1), val1)

	// Second increment
	val2, err := client.Incr(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, int64(2), val2)

	// Cleanup
	_ = client.Del(ctx, key)
}

func TestRedisClient_Hash(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:hash"

	// Set hash fields
	err := client.HSet(ctx, key, "field1", "value1", "field2", "value2")
	require.NoError(t, err)

	// Get a single field
	val, err := client.HGet(ctx, key, "field1")
	require.NoError(t, err)
	assert.Equal(t, "value1", val)

	// Get all fields
	allFields, err := client.HGetAll(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, 2, len(allFields))
	assert.Equal(t, "value1", allFields["field1"])
	assert.Equal(t, "value2", allFields["field2"])

	// Cleanup
	_ = client.Del(ctx, key)
}

func TestRedisClient_Set(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	ctx := context.Background()
	key := "test:set"

	// Add set members
	err := client.SAdd(ctx, key, "member1", "member2", "member3")
	require.NoError(t, err)

	// Check if member exists
	exists, err := client.SIsMember(ctx, key, "member1")
	require.NoError(t, err)
	assert.True(t, exists)

	// Get all members
	members, err := client.SMembers(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, 3, len(members))

	// Cleanup
	_ = client.Del(ctx, key)
}
