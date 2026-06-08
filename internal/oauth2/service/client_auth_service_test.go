package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

func hashSecret(t *testing.T, secret string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}

func TestClientAuthenticator_PublicClient(t *testing.T) {
	auth := &ClientAuthenticator{}
	client := &domain.OAuth2Client{
		IsConfidential: false,
	}
	assert.NoError(t, auth.AuthenticateClient(client, ""))
	assert.NoError(t, auth.AuthenticateClient(client, "any-secret"))
}

func TestClientAuthenticator_ConfidentialClient_EmptySecret(t *testing.T) {
	auth := &ClientAuthenticator{}
	client := &domain.OAuth2Client{
		IsConfidential:   true,
		ClientSecretHash: hashSecret(t, "real-secret"),
	}
	err := auth.AuthenticateClient(client, "")
	assert.ErrorIs(t, err, ErrClientSecretRequired)
}

func TestClientAuthenticator_ConfidentialClient_WrongSecret(t *testing.T) {
	auth := &ClientAuthenticator{}
	client := &domain.OAuth2Client{
		IsConfidential:   true,
		ClientSecretHash: hashSecret(t, "real-secret"),
	}
	err := auth.AuthenticateClient(client, "wrong-secret")
	assert.ErrorIs(t, err, ErrInvalidClientSecret)
}

func TestClientAuthenticator_ConfidentialClient_CorrectSecret(t *testing.T) {
	auth := &ClientAuthenticator{}
	client := &domain.OAuth2Client{
		IsConfidential:   true,
		ClientSecretHash: hashSecret(t, "real-secret"),
	}
	assert.NoError(t, auth.AuthenticateClient(client, "real-secret"))
}
