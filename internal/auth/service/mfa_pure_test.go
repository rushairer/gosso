package service

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 32-byte key (64 hex chars) for AES-256 tests.
const testEncryptionKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// ──────────────────────────────────────────────
// encryptSecret / decryptSecret
// ──────────────────────────────────────────────

func TestEncryptDecryptSecret_RoundTrip(t *testing.T) {
	key, err := hex.DecodeString(testEncryptionKeyHex)
	require.NoError(t, err)

	plaintext := "JBSWY3DPEHPK3PXP"
	ciphertext, err := encryptSecret(plaintext, key)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypted, err := decryptSecret(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecryptSecret_DifferentCiphertexts(t *testing.T) {
	key, err := hex.DecodeString(testEncryptionKeyHex)
	require.NoError(t, err)

	plaintext := "JBSWY3DPEHPK3PXP"
	c1, err := encryptSecret(plaintext, key)
	require.NoError(t, err)
	c2, err := encryptSecret(plaintext, key)
	require.NoError(t, err)

	assert.NotEqual(t, c1, c2, "different nonces should produce different ciphertexts")
}

func TestDecryptSecret_WrongKey(t *testing.T) {
	key, err := hex.DecodeString(testEncryptionKeyHex)
	require.NoError(t, err)

	ciphertext, err := encryptSecret("secret", key)
	require.NoError(t, err)

	wrongKey, err := hex.DecodeString("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	require.NoError(t, err)

	_, err = decryptSecret(ciphertext, wrongKey)
	assert.Error(t, err)
}

func TestDecryptSecret_ShortCiphertext(t *testing.T) {
	key, err := hex.DecodeString(testEncryptionKeyHex)
	require.NoError(t, err)

	_, err = decryptSecret("ab", key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDecryptSecret_InvalidHex(t *testing.T) {
	key, err := hex.DecodeString(testEncryptionKeyHex)
	require.NoError(t, err)

	_, err = decryptSecret("zzzz-not-hex", key)
	assert.Error(t, err)
}

// ──────────────────────────────────────────────
// generateRandomCode
// ──────────────────────────────────────────────

func TestGenerateRandomCode(t *testing.T) {
	code, err := generateRandomCode(8)
	require.NoError(t, err)
	assert.Len(t, code, 16, "8 bytes = 16 hex chars")
	_, err = hex.DecodeString(code)
	assert.NoError(t, err, "output must be valid hex")
}

func TestGenerateRandomCode_Uniqueness(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		code, err := generateRandomCode(16)
		require.NoError(t, err)
		assert.False(t, seen[code], "duplicate code generated: %s", code)
		seen[code] = true
	}
}

func TestGenerateRandomCode_DifferentLengths(t *testing.T) {
	tests := []struct {
		bytes int
	}{
		{4},
		{8},
		{16},
		{32},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_bytes", tt.bytes), func(t *testing.T) {
			code, err := generateRandomCode(tt.bytes)
			require.NoError(t, err)
			assert.Len(t, code, tt.bytes*2)
		})
	}
}

// ──────────────────────────────────────────────
// SetBackupCodeCount / SetBackupCodeLength
// ──────────────────────────────────────────────

func TestSetBackupCodeCount(t *testing.T) {
	svc := newTestMFAService(&mockCredentialRepo{})
	assert.Equal(t, defaultBackupCodeCount, svc.backupCodeCount)

	svc.SetBackupCodeCount(20)
	assert.Equal(t, 20, svc.backupCodeCount)

	// No-op on 0
	svc.SetBackupCodeCount(0)
	assert.Equal(t, 20, svc.backupCodeCount)

	// No-op on negative
	svc.SetBackupCodeCount(-1)
	assert.Equal(t, 20, svc.backupCodeCount)
}

func TestSetBackupCodeLength(t *testing.T) {
	svc := newTestMFAService(&mockCredentialRepo{})
	assert.Equal(t, defaultBackupCodeLength, svc.backupCodeLength)

	svc.SetBackupCodeLength(10)
	assert.Equal(t, 10, svc.backupCodeLength)

	// No-op on 0
	svc.SetBackupCodeLength(0)
	assert.Equal(t, 10, svc.backupCodeLength)

	// No-op on negative
	svc.SetBackupCodeLength(-1)
	assert.Equal(t, 10, svc.backupCodeLength)

	// No-op on value exceeding upper bound (12)
	svc.SetBackupCodeLength(16)
	assert.Equal(t, 10, svc.backupCodeLength)
}

// ──────────────────────────────────────────────
// SetTOTPEncryptionKey
// ──────────────────────────────────────────────

func TestSetTOTPEncryptionKey_Valid(t *testing.T) {
	svc := newTestMFAService(&mockCredentialRepo{})

	err := svc.SetTOTPEncryptionKey(testEncryptionKeyHex)
	require.NoError(t, err)
	assert.Len(t, svc.totpEncryptionKey, 32)
}

func TestSetTOTPEncryptionKey_EmptyString(t *testing.T) {
	svc := newTestMFAService(&mockCredentialRepo{})

	err := svc.SetTOTPEncryptionKey("")
	assert.NoError(t, err)
	assert.Nil(t, svc.totpEncryptionKey)
}

func TestSetTOTPEncryptionKey_InvalidHex(t *testing.T) {
	svc := newTestMFAService(&mockCredentialRepo{})

	err := svc.SetTOTPEncryptionKey("not-valid-hex!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TOTP encryption key")
}

func TestSetTOTPEncryptionKey_WrongLength(t *testing.T) {
	svc := newTestMFAService(&mockCredentialRepo{})

	// 16 bytes (32 hex chars) instead of required 32 bytes
	err := svc.SetTOTPEncryptionKey("0123456789abcdef0123456789abcdef")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be 32 bytes")
}
