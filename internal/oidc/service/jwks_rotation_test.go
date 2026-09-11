package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	tokenService "github.com/rushairer/gosso/internal/token/service"
)

func writeRotationPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "private.pem")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	require.NoError(t, file.Close())
	return path
}

func TestJWKS_AutomaticallyTracksSigningKeyRingRevision(t *testing.T) {
	keySvc, err := tokenService.NewKeyService("", "old-kid", false, 2048, zap.NewNop())
	require.NoError(t, err)
	jwks := NewJWKSService(keySvc)

	before := unmarshalJWKS(t, jwks.GetJWKS())
	require.Len(t, before.Keys, 1)
	assert.Equal(t, "old-kid", before.Keys[0]["kid"])

	require.NoError(t, keySvc.ActivateKey(writeRotationPrivateKey(t), "new-kid"))
	during := unmarshalJWKS(t, jwks.GetJWKS())
	require.Len(t, during.Keys, 2)
	kids := []string{during.Keys[0]["kid"], during.Keys[1]["kid"]}
	assert.ElementsMatch(t, []string{"old-kid", "new-kid"}, kids)

	require.NoError(t, keySvc.RetireKey("old-kid"))
	after := unmarshalJWKS(t, jwks.GetJWKS())
	require.Len(t, after.Keys, 1)
	assert.Equal(t, "new-kid", after.Keys[0]["kid"])
}
