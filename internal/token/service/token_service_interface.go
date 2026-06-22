package service

import (
	"context"
	"time"

	"github.com/rushairer/gosso/internal/token/domain"
)

// TokenServiceInterface defines the contract for JWT and refresh token operations.
// Concrete implementation is provided by TokenService.
type TokenServiceInterface interface {
	// GenerateAccessToken generates a JWT access token (RS256).
	// Note: this always overrides ExpiresAt with the configured accessExpiry.
	GenerateAccessToken(claims *domain.AccessTokenClaims) (string, error)

	// GenerateShortLivedToken generates a JWT access token (RS256) that respects
	// the caller-provided ExpiresAt. Useful for special purposes like MFA
	// verification tokens.
	GenerateShortLivedToken(claims *domain.AccessTokenClaims) (string, error)

	// AccessExpiry returns the access token expiration duration.
	AccessExpiry() time.Duration

	// GenerateRefreshToken generates a random refresh token and stores it in Redis.
	GenerateRefreshToken(ctx context.Context, accountID, clientID, sessionID, scope string) (*domain.RefreshToken, error)

	// ValidateAccessTokenWithContext validates a JWT access token using the request context.
	ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*domain.AccessTokenClaims, error)

	// ValidateRefreshToken validates a refresh token.
	ValidateRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error)

	// RotateRefreshToken rotates refresh tokens atomically.
	RotateRefreshToken(ctx context.Context, oldToken string) (*domain.RefreshToken, error)

	// RevokeRefreshToken revokes a refresh token and removes it from the session index.
	RevokeRefreshToken(ctx context.Context, token string) error

	// RevokeAllForSession atomically revokes all refresh tokens under a given session.
	RevokeAllForSession(ctx context.Context, sessionID string) error

	// RevokeAccessToken blacklists an access token by its JTI so it can no longer be used.
	RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error

	// RevokeAccountTokens marks all access tokens for the given account as revoked.
	RevokeAccountTokens(ctx context.Context, accountID string) error

	// IntrospectToken validates a token and returns its active status (RFC 7662).
	IntrospectToken(ctx context.Context, tokenString string) (map[string]any, error)

	// KeyService returns the underlying key service.
	// Exposed for OIDC JWKS endpoint (public key distribution) and ID token signing.
	KeyService() *KeyService
}
