package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewKeyService_Generate(t *testing.T) {
	svc, err := NewKeyService("", "", zap.NewNop())
	require.NoError(t, err)

	assert.NotNil(t, svc.PrivateKey())
	assert.NotNil(t, svc.PublicKey())
	assert.NotEmpty(t, svc.KeyID())
	assert.Equal(t, 2048, svc.PrivateKey().N.BitLen())
}

func TestNewKeyService_CreateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "private.pem")

	svc, err := NewKeyService(path, "", zap.NewNop())
	require.NoError(t, err)

	// The file should have been created
	_, err = os.Stat(path)
	assert.NoError(t, err)

	// Loading from the same file should succeed
	svc2, err := NewKeyService(path, "", zap.NewNop())
	require.NoError(t, err)

	// The kid of both instances should be the same (the same key)
	assert.Equal(t, svc.KeyID(), svc2.KeyID())
}

func TestNewKeyService_LoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.pem")

	// First creation
	svc1, err := NewKeyService(path, "", zap.NewNop())
	require.NoError(t, err)

	// Second loading
	svc2, err := NewKeyService(path, "", zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, svc1.KeyID(), svc2.KeyID())
	assert.Equal(t, svc1.PrivateKey().D.Bytes(), svc2.PrivateKey().D.Bytes())
}

func TestNewKeyService_CustomKeyID(t *testing.T) {
	svc, err := NewKeyService("", "my-custom-kid", zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, "my-custom-kid", svc.KeyID())
}

func TestKeyID_Stable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.pem")

	svc1, err := NewKeyService(path, "", zap.NewNop())
	require.NoError(t, err)

	svc2, err := NewKeyService(path, "", zap.NewNop())
	require.NoError(t, err)

	assert.Equal(t, svc1.KeyID(), svc2.KeyID())
}
