package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	tokenService "github.com/rushairer/gosso/internal/token/service"
)

func TestJWKSService_KeyRingAccessAndClear(t *testing.T) {
	keySvc, err := tokenService.NewKeyService("", "old-kid", false, 2048, zap.NewNop())
	require.NoError(t, err)
	jwks := NewJWKSService(keySvc)

	active, err := jwks.GetPublicKeyByKID("old-kid")
	require.NoError(t, err)
	assert.NotNil(t, active)
	assert.Len(t, jwks.GetAllPublicKeys(), 1)

	require.NoError(t, keySvc.ActivateKey(writeRotationPrivateKey(t), "new-kid"))
	assert.Len(t, jwks.GetAllPublicKeys(), 2)
	old, err := jwks.GetPublicKeyByKID("old-kid")
	require.NoError(t, err)
	assert.NotNil(t, old)

	jwks.ClearPreviousKey()
	assert.Len(t, jwks.GetAllPublicKeys(), 1)
	_, err = jwks.GetPublicKeyByKID("old-kid")
	assert.Error(t, err)
	current, err := jwks.GetPublicKeyByKID("new-kid")
	require.NoError(t, err)
	assert.NotNil(t, current)
}
