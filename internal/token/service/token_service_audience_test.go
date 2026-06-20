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

func TestGenerateAccessToken_PreservesExplicitAudience(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	tokenString, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		AccountID: "account-resource-aud",
		ClientID:  "client-resource-aud",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"api://resource"},
		},
	})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.ElementsMatch(t, jwt.ClaimStrings{"api://resource", "client-resource-aud"}, claims.Audience)
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

func TestValidateAccessTokenWithContext_RejectsClientAudienceMismatch(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	claims := &domain.AccessTokenClaims{
		AccountID: "account-aud-mismatch",
		ClientID:  "client-aud-mismatch",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-aud-mismatch",
			Issuer:    "http://localhost:8080",
			Subject:   "account-aud-mismatch",
			Audience:  jwt.ClaimStrings{"other-client"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = svc.KeyService().KeyID()
	tokenString, err := token.SignedString(svc.KeyService().PrivateKey())
	require.NoError(t, err)

	_, err = svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	assert.Error(t, err)
}
