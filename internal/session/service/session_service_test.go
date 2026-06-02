package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/session/domain"
)

func setupTestSessionService(t *testing.T) *SessionService {
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	service := NewSessionService(redisClient, logger)
	service.SetSessionTTL(10 * time.Second) // 测试用短过期时间

	return service
}

func TestSessionService_CreateAndGetSession(t *testing.T) {
	service := setupTestSessionService(t)
	defer service.redis.Close()

	ctx := context.Background()
	accountID := uuid.New()

	session := &domain.Session{
		AccountID: accountID,
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// 创建会话
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, session.ID)

	// 获取会话
	retrieved, err := service.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrieved.ID)
	assert.Equal(t, accountID, retrieved.AccountID)
	assert.Equal(t, "testuser", retrieved.Username)

	// 清理
	_ = service.DeleteSession(ctx, session.ID)
}

func TestSessionService_UpdateSession(t *testing.T) {
	service := setupTestSessionService(t)
	defer service.redis.Close()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// 创建会话
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	// 等待一小段时间
	time.Sleep(100 * time.Millisecond)

	oldLastActive := session.LastActiveAt

	// 更新会话
	session.MFAVerified = true
	err = service.UpdateSession(ctx, session)
	require.NoError(t, err)

	// 获取更新后的会话
	retrieved, err := service.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.True(t, retrieved.MFAVerified)
	assert.True(t, retrieved.LastActiveAt.After(oldLastActive))

	// 清理
	_ = service.DeleteSession(ctx, session.ID)
}

func TestSessionService_DeleteSession(t *testing.T) {
	service := setupTestSessionService(t)
	defer service.redis.Close()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// 创建会话
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	// 删除会话
	err = service.DeleteSession(ctx, session.ID)
	require.NoError(t, err)

	// 获取会话应该失败
	_, err = service.GetSession(ctx, session.ID)
	assert.Equal(t, ErrSessionNotFound, err)
}

func TestSessionService_ValidateSession(t *testing.T) {
	service := setupTestSessionService(t)
	defer service.redis.Close()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// 创建会话
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	// 验证会话（应该有效）
	validated, err := service.ValidateSession(ctx, session.ID)
	require.NoError(t, err)
	assert.NotNil(t, validated)

	// 清理
	_ = service.DeleteSession(ctx, session.ID)
}

func TestSessionService_RefreshSession(t *testing.T) {
	service := setupTestSessionService(t)
	defer service.redis.Close()

	ctx := context.Background()

	session := &domain.Session{
		AccountID: uuid.New(),
		Username:  "testuser",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}

	// 创建会话
	err := service.CreateSession(ctx, session)
	require.NoError(t, err)

	oldLastActive := session.LastActiveAt
	time.Sleep(100 * time.Millisecond)

	// 刷新会话
	err = service.RefreshSession(ctx, session.ID)
	require.NoError(t, err)

	// 获取会话，检查活跃时间是否更新
	retrieved, err := service.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.True(t, retrieved.LastActiveAt.After(oldLastActive))

	// 清理
	_ = service.DeleteSession(ctx, session.ID)
}
