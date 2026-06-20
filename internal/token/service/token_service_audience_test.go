package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rushairer/gosso/internal/token/domain"
)

func TestGenerateAccessToken_SetsClientAudience(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	tokenString, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		AccountID: "account-aud",
		ClientID:  "client-aud",
		Scope:     "openid profile",
	})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"client-aud"}, claims.Audience)
}

func TestGenerateShortLivedToken_SetsClientAudience(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	tokenString, err := svc.GenerateShortLivedToken(&domain.AccessTokenClaims{
		AccountID: "account-short-aud",
		ClientID:  "client-short-aud",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
		},
	})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"client-short-aud"}, claims.Audience)
}
