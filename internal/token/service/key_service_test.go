package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/utility"
)

func TestNewKeyService_Generate(t *testing.T) {
	svc, err := NewKeyService("", "", false, 0, zap.NewNop())
	require.NoError(t, err)

	assert.NotNil(t, svc.PrivateKey())
	assert.NotNil(t, svc.PublicKey())
	assert.NotEmpty(t, svc.KeyID())
	assert.Equal(t, 3072, svc.PrivateKey().N.BitLen())
}

func TestNewKeyService_InvalidKeyBits(t *testing.T) {
	svc, err := NewKeyService("", "", false, 1024, zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "rsa_key_bits must be at least 2048")
}

func TestNewKeyService_CreateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "private.pem")

	svc, err := NewKeyService(path, "", false, 0, zap.NewNop())
	require.NoError(t, err)

	// The file should have been created
	_, err = os.Stat(path)
	assert.NoError(t, err)

	// Loading from the same file should succeed
	svc2, err := NewKeyService(path, "", false, 0, zap.NewNop())
	require.NoError(t, err)

	// The kid of both instances should be the same (the same key)
	assert.Equal(t, svc.KeyID(), svc2.KeyID())
}

func TestNewKeyService_LoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.pem")

	// First creation
	svc1, err := NewKeyService(path, "", false, 0, zap.NewNop())
	require.NoError(t, err)

	// Second loading
	svc2, err := NewKeyService(path, "", false, 0, zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, svc1.KeyID(), svc2.KeyID())
	assert.Equal(t, svc1.PrivateKey().D.Bytes(), svc2.PrivateKey().D.Bytes())
}

func TestNewKeyService_ProductionMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "private.pem")

	// In production, loading a missing file should return an error
	_, err := NewKeyService(path, "", true, 0, zap.NewNop())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "production mode")
}

func TestNewKeyService_CustomKeyID(t *testing.T) {
	svc, err := NewKeyService("", "my-custom-kid", false, 0, zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, "my-custom-kid", svc.KeyID())
}

func TestKeyID_Stable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.pem")

	svc1, err := NewKeyService(path, "", false, 0, zap.NewNop())
	require.NoError(t, err)

	svc2, err := NewKeyService(path, "", false, 0, zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, svc1.KeyID(), svc2.KeyID())
}

// ──────────────────────────────────────────────
// BigEndianBytes table-driven test
// ──────────────────────────────────────────────

func TestBigEndianBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected []byte
	}{
		{"zero", 0, []byte{0}},
		{"one", 1, []byte{1}},
		{"255", 255, []byte{0xff}},
		{"256", 256, []byte{1, 0}},
		{"65536", 65536, []byte{1, 0, 0}},
		{"large", 0x01020304, []byte{1, 2, 3, 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := utility.BigEndianBytes(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}
