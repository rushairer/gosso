package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/testutil"
)

func setupTestConsentService(t *testing.T) (*ConsentService, func()) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := testutil.SetupTestRedis(t)
	cleanup := mr.Close

	return NewConsentService(nil, redisClient, logger), cleanup
}

func TestSaveAndGetConsent(t *testing.T) {
	svc, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	consent := &domain.Consent{
		AccountID: "account-001",
		ClientID:  "client-001",
		Scopes:    []string{"openid", "profile"},
	}

	err := svc.SaveConsent(ctx, consent)
	require.NoError(t, err)

	// Retrieve
	got, err := svc.GetConsent(ctx, "account-001", "client-001")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "account-001", got.AccountID)
	assert.Equal(t, "client-001", got.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, got.Scopes)
	assert.False(t, got.GrantedAt.IsZero())

	// Clean up
	_ = svc.DeleteConsent(ctx, "account-001", "client-001")
}

func TestGetConsent_NotFound(t *testing.T) {
	svc, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	got, err := svc.GetConsent(ctx, "nonexistent", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestDeleteConsent(t *testing.T) {
	svc, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	consent := &domain.Consent{
		AccountID: "account-002",
		ClientID:  "client-002",
		Scopes:    []string{"openid"},
	}

	err := svc.SaveConsent(ctx, consent)
	require.NoError(t, err)

	// Delete
	err = svc.DeleteConsent(ctx, "account-002", "client-002")
	require.NoError(t, err)

	// Confirm deletion
	got, err := svc.GetConsent(ctx, "account-002", "client-002")
	require.NoError(t, err)
	assert.Nil(t, got)
}
