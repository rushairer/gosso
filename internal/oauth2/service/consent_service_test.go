package service

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/testutil"
)

// mockConsentRepository is an in-memory implementation for testing.
type mockConsentRepository struct {
	store map[string]*domain.Consent
}

func newMockConsentRepository() *mockConsentRepository {
	return &mockConsentRepository{store: make(map[string]*domain.Consent)}
}

func (m *mockConsentRepository) key(accountID, clientID string) string {
	return fmt.Sprintf("%s:%s", accountID, clientID)
}

func (m *mockConsentRepository) Upsert(_ context.Context, _ *sql.Tx, consent *domain.Consent) error {
	m.store[m.key(consent.AccountID, consent.ClientID)] = consent
	return nil
}

func (m *mockConsentRepository) FindByAccountAndClient(_ context.Context, accountID, clientID string) (*domain.Consent, error) {
	c, ok := m.store[m.key(accountID, clientID)]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (m *mockConsentRepository) FindByAccountAndClientTx(_ context.Context, _ *sql.Tx, accountID, clientID string) (*domain.Consent, error) {
	return m.FindByAccountAndClient(context.Background(), accountID, clientID)
}

func (m *mockConsentRepository) SoftDelete(_ context.Context, _ *sql.Tx, accountID, clientID string, _ time.Time) error {
	delete(m.store, m.key(accountID, clientID))
	return nil
}

func (m *mockConsentRepository) FindByAccountID(_ context.Context, accountID string) ([]*domain.Consent, error) {
	var consents []*domain.Consent
	for _, c := range m.store {
		if c.AccountID == accountID {
			consents = append(consents, c)
		}
	}
	return consents, nil
}

func setupTestConsentService(t *testing.T) (*ConsentService, sqlmock.Sqlmock, func()) {
	t.Helper()
	logger := zap.NewNop()

	redisClient, mr := testutil.SetupTestRedis(t)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	repo := newMockConsentRepository()
	svc, err := NewConsentService(db, repo, redisClient, logger)
	if err != nil {
		mr.Close()
		_ = db.Close()
		t.Fatalf("NewConsentService: %v", err)
	}

	cleanup := func() {
		mr.Close()
		_ = db.Close()
	}
	return svc, mock, cleanup
}

func TestSaveAndGetConsent(t *testing.T) {
	svc, mock, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	consent := &domain.Consent{
		AccountID: "account-001",
		ClientID:  "client-001",
		Scopes:    []string{"openid", "profile"},
	}

	mock.ExpectBegin()
	mock.ExpectCommit()
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
	mock.ExpectBegin()
	mock.ExpectCommit()
	_ = svc.DeleteConsent(ctx, "account-001", "client-001")
}

func TestGetConsent_NotFound(t *testing.T) {
	svc, _, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	got, err := svc.GetConsent(ctx, "nonexistent", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestDeleteConsent(t *testing.T) {
	svc, mock, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	consent := &domain.Consent{
		AccountID: "account-002",
		ClientID:  "client-002",
		Scopes:    []string{"openid"},
	}

	mock.ExpectBegin()
	mock.ExpectCommit()
	err := svc.SaveConsent(ctx, consent)
	require.NoError(t, err)

	// Delete
	mock.ExpectBegin()
	mock.ExpectCommit()
	err = svc.DeleteConsent(ctx, "account-002", "client-002")
	require.NoError(t, err)

	// Confirm deletion
	got, err := svc.GetConsent(ctx, "account-002", "client-002")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestNewConsentService_NilRepo_ReturnsError(t *testing.T) {
	logger := zap.NewNop()
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()

	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	svc, err := NewConsentService(db, nil, redisClient, logger)
	require.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "consent repository is required")
}

func TestSaveConsent_UpdatesCache(t *testing.T) {
	svc, mock, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	consent := &domain.Consent{
		AccountID: "account-003",
		ClientID:  "client-003",
		Scopes:    []string{"openid"},
	}

	mock.ExpectBegin()
	mock.ExpectCommit()
	err := svc.SaveConsent(ctx, consent)
	require.NoError(t, err)

	// Delete from DB only — cache should still have it
	delete(svc.consentRepo.(*mockConsentRepository).store, "account-003:client-003")

	// GetConsent should return from cache even though DB has no record
	got, err := svc.GetConsent(ctx, "account-003", "client-003")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "account-003", got.AccountID)
}

func TestGetConsent_CacheMiss_FallbackToDB(t *testing.T) {
	svc, _, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()

	// Save directly to DB (mock repo), bypassing cache
	repo := svc.consentRepo.(*mockConsentRepository)
	now := time.Now()
	repo.store["account-004:client-004"] = &domain.Consent{
		AccountID: "account-004",
		ClientID:  "client-004",
		Scopes:    []string{"profile"},
		GrantedAt: now,
	}

	// GetConsent should find it via DB fallback
	got, err := svc.GetConsent(ctx, "account-004", "client-004")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []string{"profile"}, got.Scopes)
}

func TestGetConsent_CorruptCache(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := newMockConsentRepository()
	svc, err := NewConsentService(db, repo, redisClient, zap.NewNop())
	require.NoError(t, err)

	ctx := context.Background()

	// Set corrupt data in Redis cache
	_ = mr.Set("consent:acct-001:client-001", "{corrupt")

	// DB has valid data
	repo.store["acct-001:client-001"] = &domain.Consent{
		AccountID: "acct-001",
		ClientID:  "client-001",
		Scopes:    []string{"openid"},
	}

	got, err := svc.GetConsent(ctx, "acct-001", "client-001")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "acct-001", got.AccountID)
	assert.Equal(t, []string{"openid"}, got.Scopes)
}

func TestGetConsent_CacheReadError(t *testing.T) {
	redisClient, mr := testutil.SetupTestRedis(t)
	defer mr.Close()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := newMockConsentRepository()
	svc, err := NewConsentService(db, repo, redisClient, zap.NewNop())
	require.NoError(t, err)

	ctx := context.Background()

	// DB has valid data
	repo.store["acct-001:client-001"] = &domain.Consent{
		AccountID: "acct-001",
		ClientID:  "client-001",
		Scopes:    []string{"openid"},
	}

	// Close Redis to simulate connection error (not ErrKeyNotFound)
	mr.Close()

	got, err := svc.GetConsent(ctx, "acct-001", "client-001")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "acct-001", got.AccountID)
}

func TestSaveConsent_DBError(t *testing.T) {
	svc, mock, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()
	mock.ExpectBegin().WillReturnError(fmt.Errorf("db unavailable"))

	consent := &domain.Consent{
		AccountID: "account-001",
		ClientID:  "client-001",
	}
	err := svc.SaveConsent(ctx, consent)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "save consent to DB")
}

func TestDeleteConsent_DBError(t *testing.T) {
	svc, mock, cleanup := setupTestConsentService(t)
	defer cleanup()

	ctx := context.Background()
	mock.ExpectBegin().WillReturnError(fmt.Errorf("db unavailable"))

	err := svc.DeleteConsent(ctx, "account-001", "client-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete consent from DB")
}
