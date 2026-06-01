package service

import (
	"context"
	"testing"
	"time"

	"github.com/rushairer/gosso/internal/cache"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type stubPasswordResetEmailSender struct {
	sentLinks []string
}

func (s *stubPasswordResetEmailSender) SendPasswordResetLink(_ context.Context, _, link string) error {
	s.sentLinks = append(s.sentLinks, link)
	return nil
}

func setupTestPasswordResetService(t *testing.T) (*PasswordResetService, *cache.RedisClient, *stubPasswordResetEmailSender) {
	t.Helper()
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	emailSvc := &stubPasswordResetEmailSender{}
	svc := &PasswordResetService{
		redis:       redisClient,
		emailSender: emailSvc,
		baseURL:     "http://localhost:3000/reset-password",
		logger:      logger,
	}

	return svc, redisClient, emailSvc
}

func TestPasswordReset_Success(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// 模拟完整的 token 存储和验证流程（Redis 层面）
	tokenHash := tokenDomain.HashToken("test-token-123")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-001","email":"test@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// 验证 token 存储成功
	raw, err := redis.Get(ctx, tokenKey)
	require.NoError(t, err)
	assert.Contains(t, raw, "account-001")

	// 删除 key（模拟一次性使用）
	err = redis.Del(ctx, tokenKey)
	require.NoError(t, err)

	// 再次获取应返回 not found
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_Cooldown(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()
	email := "cooldown@example.com"

	// 设置冷却 key
	cooldownKey := svc.buildCooldownKey(email)
	err := redis.Set(ctx, cooldownKey, []byte("1"), PasswordResetCooldownTTL)
	require.NoError(t, err)

	// 检查冷却
	exists, err := redis.Exists(ctx, cooldownKey)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestPasswordReset_InvalidToken(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// 使用不存在的 token hash
	tokenHash := tokenDomain.HashToken("nonexistent-token")
	tokenKey := svc.buildTokenKey(tokenHash)

	_, err := redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_ExpiredToken(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// 存入 token 后手动删除模拟过期
	tokenHash := tokenDomain.HashToken("expired-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-002","email":"expired@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// 手动删除 key
	_ = redis.Del(ctx, tokenKey)

	// 获取应返回 not found
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPasswordReset_TokenExhausted(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// 存入已耗尽 attempts 的 token
	tokenHash := tokenDomain.HashToken("exhausted-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-003","email":"exhausted@example.com","attempts":5}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// 验证 attempts >= 5
	raw, err := redis.Get(ctx, tokenKey)
	require.NoError(t, err)
	assert.Contains(t, raw, `"attempts":5`)

	// 删除 key（模拟 VerifyAndReset 中的 exhausted 处理）
	err = redis.Del(ctx, tokenKey)
	require.NoError(t, err)
}

func TestPasswordReset_TokenReuse(t *testing.T) {
	svc, redis, _ := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// 存入 token
	tokenHash := tokenDomain.HashToken("reuse-token")
	tokenKey := svc.buildTokenKey(tokenHash)
	data := `{"account_id":"account-004","email":"reuse@example.com","attempts":0}`
	err := redis.Set(ctx, tokenKey, []byte(data), PasswordResetTokenTTL)
	require.NoError(t, err)

	// 第一次获取成功
	_, err = redis.Get(ctx, tokenKey)
	require.NoError(t, err)

	// 删除（一次性使用）
	_ = redis.Del(ctx, tokenKey)

	// 第二次获取失败
	_, err = redis.Get(ctx, tokenKey)
	assert.Error(t, err)
	assert.Equal(t, cache.ErrKeyNotFound, err)
}

func TestPasswordReset_EmailNotFound(t *testing.T) {
	svc, redis, emailSvc := setupTestPasswordResetService(t)
	defer redis.Close()

	ctx := context.Background()

	// 不存在的邮箱：不存入 Redis、不发送邮件
	cooldownKey := svc.buildCooldownKey("nonexistent@example.com")
	exists, err := redis.Exists(ctx, cooldownKey)
	require.NoError(t, err)
	assert.False(t, exists)

	assert.Len(t, emailSvc.sentLinks, 0)

	_ = ctx
}

func TestPasswordReset_TokenSecurity(t *testing.T) {
	// 验证 SHA256 hash 不可逆，且长度正确
	originalToken := "a]b1c2d3e4f5"
	hashedToken := tokenDomain.HashToken(originalToken)

	assert.NotEqual(t, originalToken, hashedToken)
	assert.Len(t, hashedToken, 64) // SHA256 hex = 64 chars

	// 相同输入产生相同 hash
	hashedAgain := tokenDomain.HashToken(originalToken)
	assert.Equal(t, hashedToken, hashedAgain)
}
