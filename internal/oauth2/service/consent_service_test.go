package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
)

func setupTestConsentService(t *testing.T) *ConsentService {
	logger := zap.NewNop()
	dsn := "redis://localhost:6379/15"

	redisClient, err := cache.NewRedisClient(dsn, 10, 5*time.Second, logger)
	if err != nil {
		t.Skip("Redis not available, skipping test:", err)
	}

	return NewConsentService(redisClient, logger)
}

func TestSaveAndGetConsent(t *testing.T) {
	svc := setupTestConsentService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	consent := &domain.Consent{
		AccountID: "account-001",
		ClientID:  "client-001",
		Scopes:    []string{"openid", "profile"},
	}

	err := svc.SaveConsent(ctx, consent)
	require.NoError(t, err)

	// 获取
	got, err := svc.GetConsent(ctx, "account-001", "client-001")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "account-001", got.AccountID)
	assert.Equal(t, "client-001", got.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, got.Scopes)
	assert.False(t, got.GrantedAt.IsZero())

	// 清理
	_ = svc.DeleteConsent(ctx, "account-001", "client-001")
}

func TestGetConsent_NotFound(t *testing.T) {
	svc := setupTestConsentService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	got, err := svc.GetConsent(ctx, "nonexistent", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestDeleteConsent(t *testing.T) {
	svc := setupTestConsentService(t)
	defer svc.redis.Close()

	ctx := context.Background()

	consent := &domain.Consent{
		AccountID: "account-002",
		ClientID:  "client-002",
		Scopes:    []string{"openid"},
	}

	err := svc.SaveConsent(ctx, consent)
	require.NoError(t, err)

	// 删除
	err = svc.DeleteConsent(ctx, "account-002", "client-002")
	require.NoError(t, err)

	// 确认已删除
	got, err := svc.GetConsent(ctx, "account-002", "client-002")
	require.NoError(t, err)
	assert.Nil(t, got)
}
