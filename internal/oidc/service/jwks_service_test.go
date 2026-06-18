package service

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	tokenService "github.com/rushairer/gosso/internal/token/service"
)

func newTestJWKSService(t *testing.T) *JWKSService {
	t.Helper()
	keySvc, err := tokenService.NewKeyService("", "test-kid", false, 0, zap.NewNop())
	require.NoError(t, err)
	return NewJWKSService(keySvc)
}

func TestGetJWKS_ContainsKeys(t *testing.T) {
	svc := newTestJWKSService(t)
	jwks := svc.GetJWKS()

	keys, ok := jwks["keys"].([]map[string]string)
	require.True(t, ok)
	require.Len(t, keys, 1)
}

func TestGetJWKS_KeyFields(t *testing.T) {
	svc := newTestJWKSService(t)
	jwks := svc.GetJWKS()

	keys := jwks["keys"].([]map[string]string)
	key := keys[0]

	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "test-kid", key["kid"])
	assert.Equal(t, "RS256", key["alg"])
	assert.Equal(t, "sig", key["use"])
	assert.NotEmpty(t, key["n"])
	assert.NotEmpty(t, key["e"])
}

func TestGetJWKS_ValidBase64(t *testing.T) {
	svc := newTestJWKSService(t)
	jwks := svc.GetJWKS()

	keys := jwks["keys"].([]map[string]string)
	key := keys[0]

	_, errN := base64.RawURLEncoding.DecodeString(key["n"])
	assert.NoError(t, errN)

	_, errE := base64.RawURLEncoding.DecodeString(key["e"])
	assert.NoError(t, errE)
}

func TestGetJWKS_ExponentIsStandard(t *testing.T) {
	svc := newTestJWKSService(t)
	jwks := svc.GetJWKS()

	keys := jwks["keys"].([]map[string]string)
	key := keys[0]

	eBytes, err := base64.RawURLEncoding.DecodeString(key["e"])
	require.NoError(t, err)
	// Standard RSA exponent 65537 = 0x010001
	assert.Equal(t, []byte{1, 0, 1}, eBytes)
}

func TestReload_RebuildsJWKS(t *testing.T) {
	svc := newTestJWKSService(t)
	before := svc.GetJWKS()

	// Capture the "n" value before reload
	keysBefore := before["keys"].([]map[string]string)
	nBefore := keysBefore[0]["n"]

	svc.Reload()

	after := svc.GetJWKS()
	keysAfter := after["keys"].([]map[string]string)

	// Key material is unchanged (same RSA key), but the map is rebuilt
	assert.Equal(t, nBefore, keysAfter[0]["n"])
	assert.Equal(t, "test-kid", keysAfter[0]["kid"])
	assert.Equal(t, "RS256", keysAfter[0]["alg"])
}
