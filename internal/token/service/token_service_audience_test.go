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

func TestGenerateAccessToken_UserSessionDefaultsToGossoAudience(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	tokenString, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		AccountID: "account-aud",
		SessionID: "session-aud",
		Scope:     "openid profile",
	})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, domain.PrincipalTypeUserSession, claims.PrincipalType)
	assert.Equal(t, "account-aud", claims.Subject)
	assert.ElementsMatch(t, jwt.ClaimStrings{domain.GossoAPIResourceAudience}, claims.Audience)

	parsed, _, err := jwt.NewParser().ParseUnverified(tokenString, &domain.AccessTokenClaims{})
	require.NoError(t, err)
	assert.Equal(t, "at+jwt", parsed.Header["typ"])
}

func TestGenerateAccessToken_DelegatedUserPreservesExplicitAudience(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	tokenString, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		AccountID:     "account-resource-aud",
		ClientID:      "client-resource-aud",
		SessionID:     "session-resource-aud",
		PrincipalType: domain.PrincipalTypeDelegatedUser,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"api://resource"},
		},
	})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, domain.PrincipalTypeDelegatedUser, claims.PrincipalType)
	assert.Equal(t, "account-resource-aud", claims.Subject)
	assert.ElementsMatch(t, jwt.ClaimStrings{"api://resource"}, claims.Audience)
}

func TestGenerateAccessToken_ClientPrincipalRequiresAudience(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	_, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		ClientID:      "machine-client",
		PrincipalType: domain.PrincipalTypeClient,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit resource audience")
}

func TestGenerateAccessToken_ClientPrincipalUsesClientAsSubject(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	tokenString, err := svc.GenerateAccessToken(&domain.AccessTokenClaims{
		ClientID:      "machine-client",
		PrincipalType: domain.PrincipalTypeClient,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"api://machine-resource"},
		},
	})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, domain.PrincipalTypeClient, claims.PrincipalType)
	assert.Equal(t, "machine-client", claims.Subject)
	assert.Empty(t, claims.AccountID)
	assert.Empty(t, claims.SessionID)
	assert.ElementsMatch(t, jwt.ClaimStrings{"api://machine-resource"}, claims.Audience)
}

func TestGenerateShortLivedToken_DefaultsUserPrincipalToGossoAudience(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	tokenString, err := svc.GenerateShortLivedToken(&domain.AccessTokenClaims{
		AccountID: "account-short-aud",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
		},
	})
	require.NoError(t, err)

	claims, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.ElementsMatch(t, jwt.ClaimStrings{domain.GossoAPIResourceAudience}, claims.Audience)
}

func TestValidateAccessTokenWithContext_AllowsIndependentClientAndResourceClaims(t *testing.T) {
	svc, cleanup := setupTestTokenService(t)
	defer cleanup()

	claims := &domain.AccessTokenClaims{
		AccountID:     "account-aud-mismatch",
		ClientID:      "client-aud-mismatch",
		PrincipalType: domain.PrincipalTypeDelegatedUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti-aud-mismatch",
			Issuer:    "http://localhost:8080",
			Subject:   "account-aud-mismatch",
			Audience:  jwt.ClaimStrings{"api://other-resource"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = svc.KeyService().KeyID()
	token.Header["typ"] = "at+jwt"
	tokenString, err := token.SignedString(svc.KeyService().PrivateKey())
	require.NoError(t, err)

	validated, err := svc.ValidateAccessTokenWithContext(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "client-aud-mismatch", validated.ClientID)
	assert.ElementsMatch(t, jwt.ClaimStrings{"api://other-resource"}, validated.Audience)
}
