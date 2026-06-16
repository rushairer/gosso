package service

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	authDomain "github.com/rushairer/gosso/internal/auth/domain"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
)

// mockCredentialRepo implements accountRepo.CredentialRepository for testing
type mockCredentialRepo struct {
	credMap                 map[string][]*accountDomain.Credential // key: accountID:credType
	findByAccountAndTypeErr error                                  // if set, FindByAccountAndType returns this error
}

func (m *mockCredentialRepo) FindByAccountAndType(_ context.Context, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	if m.findByAccountAndTypeErr != nil {
		return nil, m.findByAccountAndTypeErr
	}
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

func (m *mockCredentialRepo) UpdateLastUsedAt(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
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

func (m *mockCredentialRepo) FindByAccountAndTypeForUpdate(_ context.Context, _ *sql.Tx, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return m.FindByAccountAndType(context.Background(), accountID, credType)
}

func (m *mockCredentialRepo) FindByAccountAndTypeTx(ctx context.Context, _ *sql.Tx, accountID string, credType accountDomain.CredentialType) ([]*accountDomain.Credential, error) {
	return m.FindByAccountAndType(ctx, accountID, credType)
}

func (m *mockCredentialRepo) FindByTypeAndIdentifierTx(ctx context.Context, _ *sql.Tx, credType accountDomain.CredentialType, identifier string) (*accountDomain.Credential, error) {
	return m.FindByTypeAndIdentifier(ctx, credType, identifier)
}

func newTestMFAService(credRepo *mockCredentialRepo) *MFAService {
	svc, err := NewMFAService(credRepo, nil, "http://localhost:8080", nil, nil)
	if err != nil {
		panic(err)
	}
	return svc
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
	svc, err := NewMFAService(credRepo, nil, "http://localhost:8080", nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
}

func TestNewMFAService_WithPasskeyService(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	pkSvc := &PasskeyService{}
	svc, err := NewMFAService(credRepo, nil, "http://localhost:8080", nil, pkSvc)
	assert.NoError(t, err)
	assert.Equal(t, pkSvc, svc.passkeySvc)
}

// ──────────────────────────────────────────────
// dbMockCredentialRepo — extends mockCredentialRepo with
// configurable VerifyFirstUnverifiedTOTP for DB-dependent tests.
// ──────────────────────────────────────────────

type dbMockCredentialRepo struct {
	*mockCredentialRepo
	verifyFirstFn func(ctx context.Context, tx *sql.Tx, accountID string) (bool, error)
	// softDeleted tracks IDs passed to SoftDeleteCredential.
	softDeleted []string
	// createdCreds tracks credential slices passed to CreateCredentials.
	createdCreds  [][]*accountDomain.Credential
	softDeleteErr error // if set, SoftDeleteCredential returns this error
	createErr     error // if set, CreateCredentials returns this error
}

func (m *dbMockCredentialRepo) VerifyFirstUnverifiedTOTP(ctx context.Context, tx *sql.Tx, accountID string) (bool, error) {
	if m.verifyFirstFn != nil {
		return m.verifyFirstFn(ctx, tx, accountID)
	}
	return false, nil
}

func (m *dbMockCredentialRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, id string, _ time.Time) error {
	if m.softDeleteErr != nil {
		return m.softDeleteErr
	}
	m.softDeleted = append(m.softDeleted, id)
	return nil
}

func (m *dbMockCredentialRepo) CreateCredentials(_ context.Context, _ *sql.Tx, creds []*accountDomain.Credential) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.createdCreds = append(m.createdCreds, creds)
	return nil
}

func newTestMFAServiceWithDB(t *testing.T, credRepo *dbMockCredentialRepo, sqlDB *sql.DB) *MFAService {
	t.Helper()
	svc, err := NewMFAService(credRepo, sqlDB, "http://localhost:8080", nil, nil)
	require.NoError(t, err)
	require.NoError(t, svc.SetTOTPEncryptionKey(testEncryptionKeyHex))
	return svc
}

func encryptTestTOTPSecret(t *testing.T, secret string) string {
	t.Helper()
	key, err := hex.DecodeString(testEncryptionKeyHex)
	require.NoError(t, err)
	encrypted, err := encryptSecret(secret, key)
	require.NoError(t, err)
	return encrypted
}

// mockWebAuthnCredRepo implements repository.WebAuthnCredentialRepository for testing.
type mockWebAuthnCredRepo struct {
	findByAccountIDResult []*authDomain.WebAuthnCredential
	findByAccountIDErr    error
}

func (m *mockWebAuthnCredRepo) CreateCredential(_ context.Context, _ *sql.Tx, _ *authDomain.WebAuthnCredential) error {
	return nil
}
func (m *mockWebAuthnCredRepo) FindByCredentialID(_ context.Context, _ string) (*authDomain.WebAuthnCredential, error) {
	return nil, nil
}
func (m *mockWebAuthnCredRepo) FindByAccountID(_ context.Context, _ string) ([]*authDomain.WebAuthnCredential, error) {
	return m.findByAccountIDResult, m.findByAccountIDErr
}
func (m *mockWebAuthnCredRepo) UpdateCredential(_ context.Context, _ *sql.Tx, _ *authDomain.WebAuthnCredential) error {
	return nil
}
func (m *mockWebAuthnCredRepo) SoftDeleteCredential(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}
func (m *mockWebAuthnCredRepo) SoftDeleteByAccountID(_ context.Context, _ *sql.Tx, _ string, _ time.Time) error {
	return nil
}

func newTestMFAServiceWithPasskeys(t *testing.T, credRepo *mockCredentialRepo, waRepo *mockWebAuthnCredRepo) *MFAService {
	t.Helper()
	pkSvc := NewPasskeyService(nil, waRepo, nil, nil, nil, nil)
	svc, err := NewMFAService(credRepo, nil, "http://localhost:8080", nil, pkSvc)
	require.NoError(t, err)
	return svc
}

// ──────────────────────────────────────────────
// EnrollTOTP
// ──────────────────────────────────────────────

func TestEnrollTOTP_Success(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	// Single transaction wrapping both delete + create
	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	enrollment, err := svc.EnrollTOTP(context.Background(), "account-001")
	require.NoError(t, err)
	assert.NotEmpty(t, enrollment.Secret)
	assert.NotEmpty(t, enrollment.OTPAuthURL)
	assert.Contains(t, enrollment.OTPAuthURL, "otpauth://totp/")
	assert.Equal(t, 1, len(credRepo.createdCreds), "should create one credential")
	assert.False(t, credRepo.createdCreds[0][0].Verified, "enrolled credential should be unverified")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestEnrollTOTP_CleansUpExistingUnverified(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:totp": {
					{ID: "old-unverified", Type: accountDomain.CredentialTypeTOTP, Verified: false},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	// Single transaction wrapping both delete + create
	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	_, err = svc.EnrollTOTP(context.Background(), "account-001")
	require.NoError(t, err)
	assert.Contains(t, credRepo.softDeleted, "old-unverified", "old unverified TOTP should be soft-deleted")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// ActivateTOTP
// ──────────────────────────────────────────────

func TestActivateTOTP_Success(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	// Generate a real TOTP secret so VerifyTOTP can validate the code.
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "http://localhost:8080", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:totp": {
					// Verified credential with the same secret — required for VerifyTOTP to pass.
					{ID: "totp-verified", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
					// Unverified credential to be activated.
					{ID: "totp-unverified", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: false},
				},
			},
		},
		verifyFirstFn: func(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
			return true, nil
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	err = svc.ActivateTOTP(context.Background(), "account-001", code)
	assert.NoError(t, err)
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestActivateTOTP_InvalidCode(t *testing.T) {
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "http://localhost:8080", AccountName: "account-001"})
	require.NoError(t, err)
	storedSecret := encryptTestTOTPSecret(t, key.Secret())

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:totp": {
					{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	err = svc.ActivateTOTP(context.Background(), "account-001", "000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP code")
}

func TestActivateTOTP_NoPendingEnrollment(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "http://localhost:8080", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()
	storedSecret := encryptTestTOTPSecret(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:totp": {
					{ID: "totp-verified", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: storedSecret, Verified: true},
				},
			},
		},
		// VerifyFirstUnverifiedTOTP returns false — no pending enrollment.
		verifyFirstFn: func(_ context.Context, _ *sql.Tx, _ string) (bool, error) {
			return false, nil
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	err = svc.ActivateTOTP(context.Background(), "account-001", code)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no pending TOTP enrollment found")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// DisableTOTP
// ──────────────────────────────────────────────

func TestDisableTOTP_Success(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:totp": {
					{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	err = svc.DisableTOTP(context.Background(), "account-001")
	assert.NoError(t, err)
	assert.Contains(t, credRepo.softDeleted, "totp-1")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestDisableTOTP_WithBackupCodes(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:totp": {
					{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
				},
				"account-001:backup_code": {
					{ID: "bc-1", Type: accountDomain.CredentialTypeBackupCode, Verified: true},
					{ID: "bc-2", Type: accountDomain.CredentialTypeBackupCode, Verified: true},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	err = svc.DisableTOTP(context.Background(), "account-001")
	assert.NoError(t, err)
	assert.Contains(t, credRepo.softDeleted, "totp-1")
	assert.Contains(t, credRepo.softDeleted, "bc-1")
	assert.Contains(t, credRepo.softDeleted, "bc-2")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestDisableTOTP_AlreadyDeleted(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	now := time.Now()
	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:totp": {
					{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true, DeletedAt: &now},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	err = svc.DisableTOTP(context.Background(), "account-001")
	assert.NoError(t, err)
	assert.Empty(t, credRepo.softDeleted, "already-deleted creds should not be soft-deleted again")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// GenerateBackupCodes
// ──────────────────────────────────────────────

func TestGenerateBackupCodes_Success(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	codes, err := svc.GenerateBackupCodes(context.Background(), "account-001")
	require.NoError(t, err)
	assert.Len(t, codes, defaultBackupCodeCount)
	// Each code should be 16 hex chars (8 bytes)
	for _, c := range codes {
		assert.Len(t, c, defaultBackupCodeLength*2)
	}
	// Verify stored hashes are valid bcrypt
	require.Len(t, credRepo.createdCreds, 1)
	assert.Len(t, credRepo.createdCreds[0], defaultBackupCodeCount)
	for _, cred := range credRepo.createdCreds[0] {
		assert.Equal(t, accountDomain.CredentialTypeBackupCode, cred.Type)
		assert.True(t, cred.Verified)
		assert.True(t, strings.HasPrefix(cred.Value, "$2"), "should be bcrypt hash format")
	}
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestGenerateBackupCodes_WithOldCodes(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:backup_code": {
					{ID: "old-bc-1", Type: accountDomain.CredentialTypeBackupCode, Verified: true},
					{ID: "old-bc-2", Type: accountDomain.CredentialTypeBackupCode, Verified: true},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	codes, err := svc.GenerateBackupCodes(context.Background(), "account-001")
	require.NoError(t, err)
	assert.Len(t, codes, defaultBackupCodeCount)
	assert.Contains(t, credRepo.softDeleted, "old-bc-1")
	assert.Contains(t, credRepo.softDeleted, "old-bc-2")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// VerifyBackupCode
// ──────────────────────────────────────────────

func TestVerifyBackupCode_Success(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	// Pre-hash a known code.
	knownCode := "abcdef0123456789"
	hash, err := bcrypt.GenerateFromPassword([]byte(knownCode), bcrypt.DefaultCost)
	require.NoError(t, err)

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:backup_code": {
					{ID: "bc-1", AccountID: "account-001", Type: accountDomain.CredentialTypeBackupCode, Value: string(hash), Verified: true},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	valid, err := svc.VerifyBackupCode(context.Background(), "account-001", knownCode)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Contains(t, credRepo.softDeleted, "bc-1", "used backup code should be soft-deleted")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestVerifyBackupCode_WrongCode(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-code"), bcrypt.DefaultCost)
	require.NoError(t, err)

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:backup_code": {
					{ID: "bc-1", AccountID: "account-001", Type: accountDomain.CredentialTypeBackupCode, Value: string(hash), Verified: true},
				},
			},
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	valid, err := svc.VerifyBackupCode(context.Background(), "account-001", "wrong-code")
	require.NoError(t, err)
	assert.False(t, valid)
	assert.Empty(t, credRepo.softDeleted, "wrong code should not delete anything")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestVerifyBackupCode_NoCodes(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	valid, err := svc.VerifyBackupCode(context.Background(), "account-001", "any-code")
	require.NoError(t, err)
	assert.False(t, valid)
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

// ──────────────────────────────────────────────
// IsMFAEnabled — error and passkey paths
// ──────────────────────────────────────────────

func TestIsMFAEnabled_FindByAccountAndTypeError(t *testing.T) {
	credRepo := &mockCredentialRepo{
		credMap:                 map[string][]*accountDomain.Credential{},
		findByAccountAndTypeErr: errors.New("db connection lost"),
	}
	svc := newTestMFAService(credRepo)

	enabled, err := svc.IsMFAEnabled(context.Background(), "account-001")
	assert.Error(t, err)
	assert.False(t, enabled)
}

func TestIsMFAEnabled_WithPasskeyTrue(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	waRepo := &mockWebAuthnCredRepo{
		findByAccountIDResult: []*authDomain.WebAuthnCredential{
			{ID: "wa-1"},
		},
	}
	svc := newTestMFAServiceWithPasskeys(t, credRepo, waRepo)

	enabled, err := svc.IsMFAEnabled(context.Background(), "account-001")
	require.NoError(t, err)
	assert.True(t, enabled)
}

func TestIsMFAEnabled_WithPasskeyError(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	waRepo := &mockWebAuthnCredRepo{
		findByAccountIDErr: errors.New("redis down"),
	}
	svc := newTestMFAServiceWithPasskeys(t, credRepo, waRepo)

	// Passkey error is now propagated as a fail-closed measure.
	enabled, err := svc.IsMFAEnabled(context.Background(), "account-001")
	require.Error(t, err)
	assert.False(t, enabled)
}

// ──────────────────────────────────────────────
// GetMFATypes — error and passkey paths
// ──────────────────────────────────────────────

func TestGetMFATypes_FindByAccountAndTypeError(t *testing.T) {
	credRepo := &mockCredentialRepo{
		credMap:                 map[string][]*accountDomain.Credential{},
		findByAccountAndTypeErr: errors.New("db error"),
	}
	svc := newTestMFAService(credRepo)

	types := svc.GetMFATypes(context.Background(), "account-001")
	assert.Empty(t, types, "repo error should log warning and return empty")
}

func TestGetMFATypes_WithPasskey(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	waRepo := &mockWebAuthnCredRepo{
		findByAccountIDResult: []*authDomain.WebAuthnCredential{
			{ID: "wa-1"},
		},
	}
	svc := newTestMFAServiceWithPasskeys(t, credRepo, waRepo)

	types := svc.GetMFATypes(context.Background(), "account-001")
	assert.Contains(t, types, "passkey")
	assert.NotContains(t, types, "totp")
}

func TestGetMFATypes_WithTOTPAndPasskey(t *testing.T) {
	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", Type: accountDomain.CredentialTypeTOTP, Verified: true},
			},
		},
	}
	waRepo := &mockWebAuthnCredRepo{
		findByAccountIDResult: []*authDomain.WebAuthnCredential{
			{ID: "wa-1"},
		},
	}
	svc := newTestMFAServiceWithPasskeys(t, credRepo, waRepo)

	types := svc.GetMFATypes(context.Background(), "account-001")
	assert.Contains(t, types, "totp")
	assert.Contains(t, types, "passkey")
}

func TestGetMFATypes_WithPasskeyError(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	waRepo := &mockWebAuthnCredRepo{
		findByAccountIDErr: errors.New("redis down"),
	}
	svc := newTestMFAServiceWithPasskeys(t, credRepo, waRepo)

	types := svc.GetMFATypes(context.Background(), "account-001")
	assert.Empty(t, types, "passkey error should log warning and not append passkey")
}

// ──────────────────────────────────────────────
// EnrollTOTP — encryption key and CreateCredentials error
// ──────────────────────────────────────────────

func TestEnrollTOTP_WithEncryptionKey(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	err = svc.SetTOTPEncryptionKey(testEncryptionKeyHex)
	require.NoError(t, err)

	// Single transaction wrapping both delete + create
	sqlMock.ExpectBegin()
	sqlMock.ExpectCommit()

	enrollment, err := svc.EnrollTOTP(context.Background(), "account-001")
	require.NoError(t, err)
	// The returned secret is the raw TOTP secret (for display), not the encrypted one.
	assert.NotEmpty(t, enrollment.Secret)
	// The stored value should differ from the raw secret (it is encrypted).
	assert.NotEqual(t, enrollment.Secret, credRepo.createdCreds[0][0].Value, "stored value should be encrypted")
	assert.NoError(t, sqlMock.ExpectationsWereMet())
}

func TestEnrollTOTP_CreateCredentialsError(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}},
		createErr:          errors.New("insert failed"),
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	// Single transaction — begins but CreateCredentials fails, so rollback
	sqlMock.ExpectBegin()
	sqlMock.ExpectRollback()

	_, err = svc.EnrollTOTP(context.Background(), "account-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "save totp credential")
}

func TestEnrollTOTP_RequiresEncryptionKey(t *testing.T) {
	sqlDB, _, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}},
	}
	svc, err := NewMFAService(credRepo, sqlDB, "http://localhost:8080", nil, nil)
	require.NoError(t, err)

	_, err = svc.EnrollTOTP(context.Background(), "account-001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "totp encryption key not configured")
	assert.Empty(t, credRepo.createdCreds)
}

// ──────────────────────────────────────────────
// VerifyTOTP — no credentials, encryption key, decrypt failure
// ──────────────────────────────────────────────

func TestVerifyTOTP_NoCredentials(t *testing.T) {
	credRepo := &mockCredentialRepo{credMap: map[string][]*accountDomain.Credential{}}
	svc := newTestMFAService(credRepo)

	valid, err := svc.VerifyTOTP(context.Background(), "account-001", "123456")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestVerifyTOTP_WithEncryptionKey(t *testing.T) {
	// Generate a real TOTP secret, encrypt it, store it, then verify.
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "http://localhost:8080", AccountName: "account-001"})
	require.NoError(t, err)
	secret := key.Secret()

	encKey, err := hex.DecodeString(testEncryptionKeyHex)
	require.NoError(t, err)
	encrypted, err := encryptSecret(secret, encKey)
	require.NoError(t, err)

	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: encrypted, Verified: true},
			},
		},
	}
	svc := newTestMFAService(credRepo)
	require.NoError(t, svc.SetTOTPEncryptionKey(testEncryptionKeyHex))

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	valid, err := svc.VerifyTOTP(context.Background(), "account-001", code)
	require.NoError(t, err)
	assert.True(t, valid, "should decrypt and verify the TOTP code")
}

func TestVerifyTOTP_DecryptionFailure(t *testing.T) {
	// Store a garbage encrypted value; decrypt should fail and all credentials fail → returns error.
	credRepo := &mockCredentialRepo{
		credMap: map[string][]*accountDomain.Credential{
			"account-001:totp": {
				{ID: "totp-1", AccountID: "account-001", Type: accountDomain.CredentialTypeTOTP, Value: "not-valid-encrypted-hex", Verified: true},
			},
		},
	}
	svc := newTestMFAService(credRepo)
	require.NoError(t, svc.SetTOTPEncryptionKey(testEncryptionKeyHex))

	valid, err := svc.VerifyTOTP(context.Background(), "account-001", "123456")
	require.Error(t, err)
	assert.ErrorContains(t, err, "all TOTP credentials failed to decrypt")
	assert.False(t, valid, "decrypt failure should return false with error")
}

// ──────────────────────────────────────────────
// DisableTOTP — FindByAccountAndType error
// ──────────────────────────────────────────────

func TestDisableTOTP_FindByAccountAndTypeError(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	sqlMock.ExpectBegin()
	sqlMock.ExpectRollback()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap:                 map[string][]*accountDomain.Credential{},
			findByAccountAndTypeErr: errors.New("connection refused"),
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	err = svc.DisableTOTP(context.Background(), "account-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "find totp credential")
}

// ──────────────────────────────────────────────
// GenerateBackupCodes — error paths
// ──────────────────────────────────────────────

func TestGenerateBackupCodes_FindOldCodesError(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap:                 map[string][]*accountDomain.Credential{},
			findByAccountAndTypeErr: errors.New("db error"),
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectRollback()

	_, err = svc.GenerateBackupCodes(context.Background(), "account-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "generate backup codes")
}

func TestGenerateBackupCodes_SoftDeleteOldCodesError(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap: map[string][]*accountDomain.Credential{
				"account-001:backup_code": {
					{ID: "old-bc-1", Type: accountDomain.CredentialTypeBackupCode, Verified: true},
				},
			},
		},
		softDeleteErr: errors.New("delete failed"),
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectRollback()

	_, err = svc.GenerateBackupCodes(context.Background(), "account-001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete old backup code")
}

// ──────────────────────────────────────────────
// VerifyBackupCode — FindByAccountAndTypeForUpdate error
// ──────────────────────────────────────────────

func TestVerifyBackupCode_FindByAccountAndTypeForUpdateError(t *testing.T) {
	sqlDB, sqlMock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	credRepo := &dbMockCredentialRepo{
		mockCredentialRepo: &mockCredentialRepo{
			credMap:                 map[string][]*accountDomain.Credential{},
			findByAccountAndTypeErr: errors.New("lock timeout"),
		},
	}
	svc := newTestMFAServiceWithDB(t, credRepo, sqlDB)

	sqlMock.ExpectBegin()
	sqlMock.ExpectRollback()

	valid, err := svc.VerifyBackupCode(context.Background(), "account-001", "any-code")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "find backup codes")
}
