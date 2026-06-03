package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
)

// mockCredentialRepo implements accountRepo.CredentialRepository for testing
type mockCredentialRepo struct {
	credMap map[string][]*accountDomain.Credential // key: accountID:credType
}

func (m *mockCredentialRepo) FindByAccountAndType(_ context.Context, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	key := accountID + ":" + string(credType)
	if creds, ok := m.credMap[key]; ok {
		return creds, nil
	}
	return nil, nil
}

func (m *mockCredentialRepo) FindByTypeAndIdentifier(_ context.Context, _ accountDomain.CredentialType, _ string) (*accountDomain.Credential, error) {
	return nil, nil
}

func (m *mockCredentialRepo) CreateCredentials(_ context.Context, _ *sql.Tx, _ []*accountDomain.Credential) error {
	return nil
}

func (m *mockCredentialRepo) FindPasswordCredential(_ context.Context, _ string) (*accountDomain.Credential, error) {
	return nil, nil
}

func (m *mockCredentialRepo) UpdateCredential(_ context.Context, _ *sql.Tx, _ *accountDomain.Credential) error {
	return nil
}

func (m *mockCredentialRepo) SoftDeleteCredentialsByAccount(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func (m *mockCredentialRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func (m *mockCredentialRepo) VerifyFirstUnverifiedTOTP(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
	return false, nil
}

func newTestMFAService(credRepo *mockCredentialRepo) *MFAService {
	return NewMFAService(credRepo, nil, "http://localhost:8080", nil)
}

// ──────────────────────────────────────────────
// IsMFAEnabled
// ──────────────────────────────────────────────

func TestIsMFAEnabled_TOTPVerified(t *testing.T) {
	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
			},
		},
	}
	svc := newTestMFAService(credRepo)

	enabled, err := svc.IsMFAEnabled(context.Background(), "account-001")
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestIsMFAEnabled_TOTPNotVerified(t *testing.T) {
	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: false},
			},
		},
	}
	svc := newTestMFAService(credRepo)

	enabled, err := svc.IsMFAEnabled(context.Background(), "account-001")
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsMFAEnabled_TOTPDeleted(t *testing.T) {
	now := time.Now()
	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true, DeletedAt: &now},
			},
		},
	}
	svc := newTestMFAService(credRepo)

	enabled, err := svc.IsMFAEnabled(context.Background(), "account-001")
	require.NoError(t, err)
	assert.False(t, enabled)
}

func TestIsMFAEnabled_NoTOTP(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	svc := newTestMFAService(credRepo)

	enabled, err := svc.IsMFAEnabled(context.Background(), "account-001")
	require.NoError(t, err)
	assert.False(t, enabled)
}

// ──────────────────────────────────────────────
// GetMFATypes
// ──────────────────────────────────────────────

func TestGetMFATypes_TOTPOnly(t *testing.T) {
	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
			},
		},
	}
	svc := newTestMFAService(credRepo)

	types := svc.GetMFATypes(context.Background(), "account-001")
	assert.Contains(t, types, "totp")
	assert.NotContains(t, types, "passkey")
}

func TestGetMFATypes_None(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	svc := newTestMFAService(credRepo)

	types := svc.GetMFATypes(context.Background(), "account-001")
	assert.Empty(t, types)
}

func TestGetMFATypes_UnverifiedTOTPIgnored(t *testing.T) {
	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: false},
			},
		},
	}
	svc := newTestMFAService(credRepo)

	types := svc.GetMFATypes(context.Background(), "account-001")
	assert.Empty(t, types)
}

// ──────────────────────────────────────────────
// NewMFAService
// ──────────────────────────────────────────────

func TestNewMFAService_NilLogger(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	svc := NewMFAService(credRepo, nil, "http://localhost:8080", nil)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
}

func TestNewMFAService_WithPasskeyService(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	pkSvc := &PasskeyService{}
	svc := NewMFAService(credRepo, nil, "http://localhost:8080", nil, pkSvc)
	assert.Equal(t, pkSvc, svc.passkeySvc)
}
