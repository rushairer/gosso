package repository

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/auth/domain"
)

// ──────────────────────────────────────────────
// scanWebAuthnCredential
// ──────────────────────────────────────────────

func TestScanWebAuthnCredential_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	lastUsedAt := now.Add(-1 * time.Hour)
	transports := []string{"internal", "hybrid"}
	trJSON, _ := json.Marshal(transports)

	cred := &domain.WebAuthnCredential{
		ID:              "cred-001",
		AccountID:       "account-001",
		CredentialID:    []byte("cred-id-bytes"),
		PublicKey:       []byte("public-key-bytes"),
		SignCount:       5,
		AAGUID:          []byte("aaguid-bytes"),
		AttestationType: "none",
		Name:            "My Passkey",
		Verified:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	rows := sqlmock.NewRows(webauthnColumns()).AddRow(
		cred.ID, cred.AccountID, cred.CredentialID, cred.PublicKey, cred.SignCount,
		cred.AAGUID, trJSON, cred.AttestationType, cred.Name, cred.Verified,
		cred.CreatedAt, cred.UpdatedAt, lastUsedAt, nil, // deleted_at is NULL
	)
	mock.ExpectQuery("SELECT .+ FROM webauthn_credentials").WillReturnRows(rows)

	result, err := db.Query("SELECT * FROM webauthn_credentials")
	require.NoError(t, err)
	require.True(t, result.Next())

	got, err := scanWebAuthnCredential(result)
	require.NoError(t, err)

	// 14 columns scanned
	assert.Equal(t, "cred-001", got.ID)
	assert.Equal(t, "account-001", got.AccountID)
	assert.Equal(t, []byte("cred-id-bytes"), got.CredentialID)
	assert.Equal(t, []byte("public-key-bytes"), got.PublicKey)
	assert.Equal(t, uint32(5), got.SignCount)
	assert.Equal(t, []byte("aaguid-bytes"), got.AAGUID)
	assert.Equal(t, "none", got.AttestationType)
	assert.Equal(t, "My Passkey", got.Name)
	assert.True(t, got.Verified)
	assert.False(t, got.CreatedAt.IsZero())

	// transports JSON unmarshaled
	assert.Equal(t, transports, got.Transports)

	// lastUsedAt assigned from non-NULL value
	require.NotNil(t, got.LastUsedAt)
	assert.Equal(t, lastUsedAt, *got.LastUsedAt)

	// deletedAt is nil when NULL in DB
	assert.Nil(t, got.DeletedAt)
}

func TestScanWebAuthnCredential_NilTransports(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()

	rows := sqlmock.NewRows(webauthnColumns()).AddRow(
		"cred-002", "account-002", []byte("cid"), []byte("pk"), uint32(0),
		[]byte("aaguid"), nil, "none", "Passkey", false,
		now, now, nil, nil, // transports is nil (NULL), lastUsedAt NULL, deletedAt NULL
	)
	mock.ExpectQuery("SELECT .+ FROM webauthn_credentials").WillReturnRows(rows)

	result, err := db.Query("SELECT * FROM webauthn_credentials")
	require.NoError(t, err)
	require.True(t, result.Next())

	got, err := scanWebAuthnCredential(result)
	require.NoError(t, err)

	// nil transports should not cause an error — nil-safe unmarshal
	assert.Nil(t, got.Transports)
	assert.Nil(t, got.LastUsedAt)
	assert.Nil(t, got.DeletedAt)
}

func TestScanWebAuthnCredential_NullableTimestamps(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	now := time.Now()
	lastUsedAt := now.Add(-24 * time.Hour)
	deletedAt := now.Add(-1 * time.Hour)
	trJSON, _ := json.Marshal([]string{"usb"})

	rows := sqlmock.NewRows(webauthnColumns()).AddRow(
		"cred-003", "account-003", []byte("cid"), []byte("pk"), uint32(10),
		[]byte("aaguid"), trJSON, "none", "Hardware Key", true,
		now, now, lastUsedAt, deletedAt,
	)
	mock.ExpectQuery("SELECT .+ FROM webauthn_credentials").WillReturnRows(rows)

	result, err := db.Query("SELECT * FROM webauthn_credentials")
	require.NoError(t, err)
	require.True(t, result.Next())

	got, err := scanWebAuthnCredential(result)
	require.NoError(t, err)

	// Non-NULL lastUsedAt and deletedAt are assigned as non-nil pointers
	require.NotNil(t, got.LastUsedAt)
	assert.Equal(t, lastUsedAt, *got.LastUsedAt)

	require.NotNil(t, got.DeletedAt)
	assert.Equal(t, deletedAt, *got.DeletedAt)
}
