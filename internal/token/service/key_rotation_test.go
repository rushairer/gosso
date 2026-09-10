package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/token/domain"
)

func TestSigningKeyRotation_PreservesOverlapUntilRetirement(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	oldKID := svc.KeyService().KeyID()
	oldToken, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		AccountID: "account-rotation",
		SessionID: "session-rotation",
	})
	require.NoError(t, err)

	newPrivate, err := generateKey(2048)
	require.NoError(t, err)
	newPath := filepath.Join(t.TempDir(), "rotated-private.pem")
	require.NoError(t, savePrivateKeyToPEM(newPath, newPrivate))

	require.NoError(t, svc.KeyService().ActivateKey(newPath, "rotated-kid"))
	assert.Equal(t, "rotated-kid", svc.KeyService().KeyID())

	// The old token remains valid during the verification/JWKS overlap.
	oldClaims, err := svc.ValidateAccessTokenWithContext(context.Background(), oldToken)
	require.NoError(t, err)
	assert.Equal(t, "account-rotation", oldClaims.AccountID)

	newToken, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		AccountID: "account-rotation",
		SessionID: "session-rotation-2",
	})
	require.NoError(t, err)
	_, err = svc.ValidateAccessTokenWithContext(context.Background(), newToken)
	require.NoError(t, err)

	keys := svc.KeyService().AllPublicKeys()
	assert.Contains(t, keys, oldKID)
	assert.Contains(t, keys, "rotated-kid")

	require.NoError(t, svc.KeyService().RetireKey(oldKID))
	_, err = svc.ValidateAccessTokenWithContext(context.Background(), oldToken)
	require.Error(t, err)
	_, err = svc.ValidateAccessTokenWithContext(context.Background(), newToken)
	require.NoError(t, err)
}

func TestSigningKeyRotation_RejectsKIDReuseWithDifferentMaterial(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	newPrivate, err := generateKey(2048)
	require.NoError(t, err)
	newPath := filepath.Join(t.TempDir(), "different-private.pem")
	require.NoError(t, savePrivateKeyToPEM(newPath, newPrivate))

	err = svc.KeyService().ActivateKey(newPath, svc.KeyService().KeyID())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot reuse active kid")
}
