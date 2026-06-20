package service

import (
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/oauth2/domain"
)

var (
	// ErrClientSecretRequired is returned when a confidential client omits the client_secret.
	ErrClientSecretRequired = errors.New("client_secret required")
	// ErrInvalidClientSecret is returned when the client_secret does not match the stored hash.
	ErrInvalidClientSecret = errors.New("invalid client_secret")
)

// dummyBcryptHash is a pre-computed bcrypt hash of "dummy" used for timing normalization.
// It prevents attackers from distinguishing between different failure modes via response timing.
const dummyBcryptHash = "$2a$10$0000000000000000000000000000000000000000000000000000000"

// ClientAuthenticator handles OAuth2 client authentication.
type ClientAuthenticator struct{}

// AuthenticateClient verifies client credentials.
// For confidential clients, it verifies the client_secret via bcrypt.
// For public clients, it returns nil (no secret required).
// Returns ErrClientSecretRequired or ErrInvalidClientSecret on failure.
func (a *ClientAuthenticator) AuthenticateClient(client *domain.OAuth2Client, clientSecret string) error {
	if !client.IsConfidential {
		// Timing normalization: if a secret is provided for a public client,
		// perform a dummy bcrypt comparison to prevent timing-based client type detection.
		// Without this, a ~100ms bcrypt call for confidential clients vs ~0ms for public
		// clients would let attackers determine the client type.
		if clientSecret != "" {
			_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte("dummy"))
		}
		return nil
	}
	if clientSecret == "" {
		// Timing normalization: always call bcrypt even when secret is empty
		// to prevent attackers from distinguishing "no secret provided" from
		// "wrong secret provided" via response timing.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte("dummy"))
		return ErrClientSecretRequired
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
		return ErrInvalidClientSecret
	}
	return nil
}

// DummyAuthenticate performs a dummy bcrypt comparison to mitigate timing side-channels.
// Call this when client lookup fails to make the response time indistinguishable
// from "client found, wrong secret."
func (a *ClientAuthenticator) DummyAuthenticate() {
	_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte("dummy"))
}
