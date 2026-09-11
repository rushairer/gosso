package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func writePublicKeyPEM(t *testing.T, key *rsa.PublicKey, blockType string) string {
	t.Helper()
	var der []byte
	var err error
	switch blockType {
	case "PUBLIC KEY":
		der, err = x509.MarshalPKIXPublicKey(key)
	case "RSA PUBLIC KEY":
		der = x509.MarshalPKCS1PublicKey(key)
	default:
		t.Fatalf("unsupported test block type %q", blockType)
	}
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "public.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600))
	return path
}

func TestKeyService_LoadPreviousPublicKeyAndClear(t *testing.T) {
	svc, err := NewKeyService("", "active-kid", false, 2048, zap.NewNop())
	require.NoError(t, err)
	initialRevision := svc.Revision()

	previousPrivate, err := generateKey(2048)
	require.NoError(t, err)
	previousPath := writePublicKeyPEM(t, &previousPrivate.PublicKey, "PUBLIC KEY")
	require.NoError(t, svc.LoadPreviousPublicKey(previousPath, "previous-kid"))
	assert.Greater(t, svc.Revision(), initialRevision)

	loaded, err := svc.PublicKeyByKID("previous-kid")
	require.NoError(t, err)
	assert.True(t, publicKeysEqual(&previousPrivate.PublicKey, loaded))
	assert.Contains(t, svc.AllPublicKeys(), "active-kid")
	assert.Contains(t, svc.AllPublicKeys(), "previous-kid")

	revisionWithPrevious := svc.Revision()
	svc.ClearPreviousKeys()
	assert.Greater(t, svc.Revision(), revisionWithPrevious)
	_, err = svc.PublicKeyByKID("previous-kid")
	assert.Error(t, err)
	assert.Len(t, svc.AllPublicKeys(), 1)

	revisionAfterClear := svc.Revision()
	svc.ClearPreviousKeys()
	assert.Equal(t, revisionAfterClear, svc.Revision())
}

func TestKeyService_LoadPreviousPublicKeyValidation(t *testing.T) {
	svc, err := NewKeyService("", "active-kid", false, 2048, zap.NewNop())
	require.NoError(t, err)

	assert.Error(t, svc.LoadPreviousPublicKey("", "kid"))
	assert.Error(t, svc.LoadPreviousPublicKey("/does/not/exist.pem", "kid"))

	activePath := writePublicKeyPEM(t, svc.PublicKey(), "PUBLIC KEY")
	require.NoError(t, svc.LoadPreviousPublicKey(activePath, "active-kid"))

	otherPrivate, err := generateKey(2048)
	require.NoError(t, err)
	otherPath := writePublicKeyPEM(t, &otherPrivate.PublicKey, "PUBLIC KEY")
	err = svc.LoadPreviousPublicKey(otherPath, "active-kid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicts with active signing key")
}

func TestLoadPublicKeyFromPEMFormatsAndErrors(t *testing.T) {
	private, err := generateKey(2048)
	require.NoError(t, err)

	for _, blockType := range []string{"PUBLIC KEY", "RSA PUBLIC KEY"} {
		t.Run(blockType, func(t *testing.T) {
			path := writePublicKeyPEM(t, &private.PublicKey, blockType)
			loaded, loadErr := loadPublicKeyFromPEM(path)
			require.NoError(t, loadErr)
			assert.True(t, publicKeysEqual(&private.PublicKey, loaded))
		})
	}

	privatePath := filepath.Join(t.TempDir(), "private.pem")
	require.NoError(t, savePrivateKeyToPEM(privatePath, private))
	loaded, err := loadPublicKeyFromPEM(privatePath)
	require.NoError(t, err)
	assert.True(t, publicKeysEqual(&private.PublicKey, loaded))

	invalidPath := filepath.Join(t.TempDir(), "invalid.pem")
	require.NoError(t, os.WriteFile(invalidPath, []byte("not pem"), 0600))
	_, err = loadPublicKeyFromPEM(invalidPath)
	assert.Error(t, err)

	unsupportedPath := filepath.Join(t.TempDir(), "unsupported.pem")
	require.NoError(t, os.WriteFile(unsupportedPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("test")}), 0600))
	_, err = loadPublicKeyFromPEM(unsupportedPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PEM block type")

	smallPrivate, err := generateKey(1024)
	require.NoError(t, err)
	smallPath := writePublicKeyPEM(t, &smallPrivate.PublicKey, "PUBLIC KEY")
	_, err = loadPublicKeyFromPEM(smallPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key too small")
}

func TestKeyService_ActivateAndRetireValidation(t *testing.T) {
	svc, err := NewKeyService("", "active-kid", false, 2048, zap.NewNop())
	require.NoError(t, err)

	assert.Error(t, svc.ActivateKey("", "new-kid"))
	assert.Error(t, svc.ActivateKey("/does/not/exist.pem", "new-kid"))
	assert.Error(t, svc.RetireKey(""))
	assert.Error(t, svc.RetireKey("active-kid"))
	assert.Error(t, svc.RetireKey("missing-kid"))

	samePath := filepath.Join(t.TempDir(), "same-private.pem")
	require.NoError(t, savePrivateKeyToPEM(samePath, svc.PrivateKey()))
	require.NoError(t, svc.ActivateKey(samePath, "active-kid"))

	oldKID := svc.KeyID()
	oldRevision := svc.Revision()
	newPrivate, err := generateKey(2048)
	require.NoError(t, err)
	newPath := filepath.Join(t.TempDir(), "new-private.pem")
	require.NoError(t, savePrivateKeyToPEM(newPath, newPrivate))
	require.NoError(t, svc.ActivateKey(newPath, ""))
	assert.NotEqual(t, oldKID, svc.KeyID())
	assert.Greater(t, svc.Revision(), oldRevision)
	assert.Contains(t, svc.AllPublicKeys(), oldKID)

	require.NoError(t, svc.RetireKey(oldKID))
	assert.NotContains(t, svc.AllPublicKeys(), oldKID)
}

func TestKeyService_ActivateRejectsRetainedKIDCollision(t *testing.T) {
	svc, err := NewKeyService("", "active-kid", false, 2048, zap.NewNop())
	require.NoError(t, err)

	retainedPrivate, err := generateKey(2048)
	require.NoError(t, err)
	retainedPath := writePublicKeyPEM(t, &retainedPrivate.PublicKey, "PUBLIC KEY")
	require.NoError(t, svc.LoadPreviousPublicKey(retainedPath, "reserved-kid"))

	candidate, err := generateKey(2048)
	require.NoError(t, err)
	candidatePath := filepath.Join(t.TempDir(), "candidate.pem")
	require.NoError(t, savePrivateKeyToPEM(candidatePath, candidate))
	err = svc.ActivateKey(candidatePath, "reserved-kid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists in retained key ring")
}

func TestKeyService_EmptyKeyStateDefensivePaths(t *testing.T) {
	svc := &KeyService{previousKeys: make(map[string]*rsa.PublicKey), logger: zap.NewNop()}
	assert.Nil(t, svc.PublicKey())
	assert.Empty(t, svc.AllPublicKeys())
	_, err := svc.PublicKeyByKID("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active signing key is unavailable")
}
