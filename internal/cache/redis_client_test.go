package cache

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupTestRedisClient(t *testing.T) (*RedisClient, *miniredis.Miniredis) {
	t.Helper()
	requireLocalTCPListen(t, "tcp4", "127.0.0.1:0")
	logger := zap.NewNop()

	mr := miniredis.RunT(t)
	client, err := NewRedisClient(context.Background(), "redis://"+mr.Addr(), 10, 5*time.Second, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create test redis client: %v", err)
	}

	return client, mr
}

func requireLocalTCPListen(t *testing.T, network, address string) {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Skipf("skipping: local TCP listen unavailable (%s %s): %v", network, address, err)
	}
	require.NoError(t, ln.Close())
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

// ──────────────────────────────────────────────
// Close / Ping
// ──────────────────────────────────────────────

func TestRedisClient_Ping(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

	assert.NoError(t, client.Ping(context.Background()))
}

func TestRedisClient_Close(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

	assert.NoError(t, client.Close())
}

// ──────────────────────────────────────────────
// Exists
// ──────────────────────────────────────────────

func TestRedisClient_Exists(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	ok, err := client.Exists(ctx, "no-such-key")
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, client.Set(ctx, "exists-key", "v", 10*time.Second))
	ok, err = client.Exists(ctx, "exists-key")
	require.NoError(t, err)
	assert.True(t, ok)
}

// ──────────────────────────────────────────────
// Expire
// ──────────────────────────────────────────────

func TestRedisClient_Expire(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	require.NoError(t, client.Set(ctx, "expire-key", "v", 0))
	require.NoError(t, client.Expire(ctx, "expire-key", 5*time.Second))

	d, err := client.TTL(ctx, "expire-key")
	require.NoError(t, err)
	assert.Greater(t, d, time.Duration(0))
}

// ──────────────────────────────────────────────
// Decr
// ──────────────────────────────────────────────

func TestRedisClient_Decr(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	require.NoError(t, client.Set(ctx, "decr-key", "10", 0))
	v, err := client.Decr(ctx, "decr-key")
	require.NoError(t, err)
	assert.Equal(t, int64(9), v)
}

// ──────────────────────────────────────────────
// SetNX
// ──────────────────────────────────────────────

func TestRedisClient_SetNX(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	ok, err := client.SetNX(ctx, "lock-key", "owner", 10*time.Second)
	require.NoError(t, err)
	assert.True(t, ok)

	// Second call should fail (key already exists)
	ok, err = client.SetNX(ctx, "lock-key", "other", 10*time.Second)
	require.NoError(t, err)
	assert.False(t, ok)
}

// ──────────────────────────────────────────────
// HDel
// ──────────────────────────────────────────────

func TestRedisClient_HDel(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	require.NoError(t, client.HSet(ctx, "hdel-key", "f1", "v1", "f2", "v2"))
	require.NoError(t, client.HDel(ctx, "hdel-key", "f1"))

	_, err := client.HGet(ctx, "hdel-key", "f1")
	assert.Equal(t, ErrKeyNotFound, err)

	v, err := client.HGet(ctx, "hdel-key", "f2")
	require.NoError(t, err)
	assert.Equal(t, "v2", v)
}

// ──────────────────────────────────────────────
// HGet not found
// ──────────────────────────────────────────────

func TestRedisClient_HGet_NotFound(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

	_, err := client.HGet(context.Background(), "no-hash", "no-field")
	assert.Equal(t, ErrKeyNotFound, err)
}

// ──────────────────────────────────────────────
// SAddWithTTL
// ──────────────────────────────────────────────

func TestRedisClient_SAddWithTTL(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	err := client.SAddWithTTL(ctx, "sattl-key", "m1", 10*time.Second)
	require.NoError(t, err)

	ok, err := client.SIsMember(ctx, "sattl-key", "m1")
	require.NoError(t, err)
	assert.True(t, ok)

	d, err := client.TTL(ctx, "sattl-key")
	require.NoError(t, err)
	assert.Greater(t, d, time.Duration(0))
}

// ──────────────────────────────────────────────
// SRem
// ──────────────────────────────────────────────

func TestRedisClient_SRem(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	require.NoError(t, client.SAdd(ctx, "srem-key", "a", "b", "c"))
	require.NoError(t, client.SRem(ctx, "srem-key", "b"))

	ok, err := client.SIsMember(ctx, "srem-key", "b")
	require.NoError(t, err)
	assert.False(t, ok)
}

// ──────────────────────────────────────────────
// TTL
// ──────────────────────────────────────────────

func TestRedisClient_TTL_NoExpiry(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	require.NoError(t, client.Set(ctx, "ttl-key", "v", 0))
	d, err := client.TTL(ctx, "ttl-key")
	require.NoError(t, err)
	assert.Equal(t, time.Duration(-1), d)
}

// ──────────────────────────────────────────────
// GetClient / RunScript
// ──────────────────────────────────────────────

func TestRedisClient_GetClient(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

	assert.NotNil(t, client.GetClient())
}

func TestRedisClient_RunScript(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	require.NoError(t, client.Set(ctx, "script-key", "42", 0))

	script := redis.NewScript(`return redis.call('GET', KEYS[1])`)
	val, err := client.RunScript(ctx, script, []string{"script-key"}).Result()
	require.NoError(t, err)
	assert.Equal(t, "42", val)
}

// ──────────────────────────────────────────────
// IncrWithExpiry
// ──────────────────────────────────────────────

func TestRedisClient_IncrWithExpiry(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()
	key := "iwe-key"

	v, err := client.IncrWithExpiry(ctx, key, 60*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)

	v, err = client.IncrWithExpiry(ctx, key, 60*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int64(2), v)
}

// ──────────────────────────────────────────────
// CheckAndIncr
// ──────────────────────────────────────────────

func TestRedisClient_CheckAndIncr(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()
	key := "cai-key"

	// First call: count=0 < limit=2 → should increment to 1
	v, err := client.CheckAndIncr(ctx, key, 2, 60*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)

	// Second call: count=1 < limit=2 → should increment to 2
	v, err = client.CheckAndIncr(ctx, key, 2, 60*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int64(2), v)

	// Third call: count=2 >= limit=2 → should NOT increment, return 2
	v, err = client.CheckAndIncr(ctx, key, 2, 60*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int64(2), v)
}

// ──────────────────────────────────────────────
// SetIfExists
// ──────────────────────────────────────────────

func TestRedisClient_SetIfExists(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Key doesn't exist → false
	ok, err := client.SetIfExists(ctx, "sif-key", "val", 60*time.Second)
	require.NoError(t, err)
	assert.False(t, ok)

	// Create key, then SetIfExists → true
	require.NoError(t, client.Set(ctx, "sif-key", "old", 0))
	ok, err = client.SetIfExists(ctx, "sif-key", "new", 60*time.Second)
	require.NoError(t, err)
	assert.True(t, ok)

	v, err := client.Get(ctx, "sif-key")
	require.NoError(t, err)
	assert.Equal(t, "new", v)
}

// ──────────────────────────────────────────────
// GetDel
// ──────────────────────────────────────────────

func TestRedisClient_GetDel(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	// Non-existent key returns ErrKeyNotFound
	v, err := client.GetDel(ctx, "gd-key")
	require.ErrorIs(t, err, ErrKeyNotFound)
	assert.Equal(t, "", v)

	// Set and GetDel
	require.NoError(t, client.Set(ctx, "gd-key", "value", 0))
	v, err = client.GetDel(ctx, "gd-key")
	require.NoError(t, err)
	assert.Equal(t, "value", v)

	// Key is gone
	_, err = client.Get(ctx, "gd-key")
	assert.Equal(t, ErrKeyNotFound, err)
}

// ──────────────────────────────────────────────
// NewRedisClient — invalid DSN
// ──────────────────────────────────────────────

func TestNewRedisClient_InvalidDSN(t *testing.T) {
	_, err := NewRedisClient(context.Background(), "not-a-valid-dsn", 10, 5*time.Second, nil)
	assert.Error(t, err)
}

// ──────────────────────────────────────────────
// Parallel-safe stress: many IncrWithExpiry calls
// ──────────────────────────────────────────────

func TestRedisClient_IncrWithExpiry_Concurrent(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()
	ctx := context.Background()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = client.IncrWithExpiry(ctx, "concurrent-key", 10*time.Second)
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	v, err := client.Get(ctx, "concurrent-key")
	require.NoError(t, err)
	assert.Equal(t, "10", v)
}

// ──────────────────────────────────────────────
// Error paths via closed client
// ──────────────────────────────────────────────

// TestRedisClient_ClosedClient_Errors verifies that all methods properly return
// errors when the underlying Redis connection is closed, covering the error
// handling branches (if err != nil) in each wrapper method.
func TestRedisClient_ClosedClient_Errors(t *testing.T) {
	client, mr := setupTestRedisClient(t)
	defer mr.Close()

	// Close the underlying Redis client to make all subsequent operations fail
	// with redis.ErrClosed. This is deterministic and avoids port-reuse races.
	require.NoError(t, client.GetClient().Close())

	ctx := context.Background()

	assert.Error(t, client.Set(ctx, "k", "v", 0))

	_, err := client.Get(ctx, "k")
	assert.Error(t, err)

	assert.Error(t, client.Del(ctx, "k"))

	_, err = client.Exists(ctx, "k")
	assert.Error(t, err)

	assert.Error(t, client.Expire(ctx, "k", time.Second))

	_, err = client.Incr(ctx, "k")
	assert.Error(t, err)

	_, err = client.Decr(ctx, "k")
	assert.Error(t, err)

	_, err = client.SetNX(ctx, "k", "v", time.Second)
	assert.Error(t, err)

	assert.Error(t, client.HSet(ctx, "k", "f", "v"))

	_, err = client.HGet(ctx, "k", "f")
	assert.Error(t, err)

	_, err = client.HGetAll(ctx, "k")
	assert.Error(t, err)

	assert.Error(t, client.HDel(ctx, "k", "f"))

	assert.Error(t, client.SAdd(ctx, "k", "v"))

	assert.Error(t, client.SAddWithTTL(ctx, "k", "v", time.Second))

	_, err = client.SMembers(ctx, "k")
	assert.Error(t, err)

	_, err = client.SIsMember(ctx, "k", "v")
	assert.Error(t, err)

	assert.Error(t, client.SRem(ctx, "k", "v"))

	_, err = client.TTL(ctx, "k")
	assert.Error(t, err)

	_, err = client.IncrWithExpiry(ctx, "k", time.Second)
	assert.Error(t, err)

	_, err = client.CheckAndIncr(ctx, "k", 5, time.Second)
	assert.Error(t, err)

	_, err = client.SetIfExists(ctx, "k", "v", time.Second)
	assert.Error(t, err)

	_, err = client.GetDel(ctx, "k")
	assert.Error(t, err)

	assert.Error(t, client.Ping(ctx))
}

// ──────────────────────────────────────────────
// NewRedisClient — nil logger and Ping failure
// ──────────────────────────────────────────────

func TestNewRedisClient_NilLogger(t *testing.T) {
	requireLocalTCPListen(t, "tcp4", "127.0.0.1:0")
	mr := miniredis.RunT(t)
	defer mr.Close()

	client, err := NewRedisClient(context.Background(), "redis://"+mr.Addr(), 10, 5*time.Second, nil)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NoError(t, client.Close())
}

func TestNewRedisClient_PingFailure(t *testing.T) {
	requireLocalTCPListen(t, "tcp4", "127.0.0.1:0")
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	// Close server before client connects → immediate "connection refused"
	mr.Close()

	_, err := NewRedisClient(context.Background(), "redis://"+addr, 10, 5*time.Second, zap.NewNop())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ping redis")
}
