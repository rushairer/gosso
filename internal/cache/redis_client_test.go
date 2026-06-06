package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupTestRedisClient(t *testing.T) (*RedisClient, *miniredis.Miniredis) {
	t.Helper()
	logger := zap.NewNop()

	mr := miniredis.RunT(t)
	client, err := NewRedisClient("redis://"+mr.Addr(), 10, 5*time.Second, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create test redis client: %v", err)
	}

	return client, mr
}

func TestRedisClient_SetGet(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

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
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

	ctx := context.Background()
	key := "test:nonexistent"

	_, err := client.Get(ctx, key)
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestRedisClient_Expiration(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

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

	// Fast-forward miniredis time to trigger expiration
	mr.FastForward(2 * time.Second)

	// Should have expired
	_, err = client.Get(ctx, key)
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestRedisClient_Incr(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

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
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

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
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

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
