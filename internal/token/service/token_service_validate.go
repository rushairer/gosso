package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const accessTokenClockSkew = 30 * time.Second

// ValidateAccessTokenWithContext validates a JWT access token using the request context
func (s *TokenService) ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*domain.AccessTokenClaims, error) {
	parser := jwt.NewParser(jwt.WithIssuer(s.issuer), jwt.WithLeeway(accessTokenClockSkew))
	token, err := parser.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Enforce RS256 specifically to prevent algorithm downgrade attacks (e.g., RS384/RS512).
		if token.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", token.Method.Alg())
		}
		return s.keySvc.PublicKey(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}

	claims, ok := token.Claims.(*domain.AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// OAuth client-bound tokens must carry an audience matching their client_id.
	// This keeps newly issued tokens standards-compliant and rejects malformed
	// tokens that include client_id but omit or mismatch aud.
	if claims.ClientID != "" && !slices.Contains(claims.Audience, claims.ClientID) {
		return nil, ErrInvalidToken
	}

	// Pipeline blacklist + account-revocation checks in a single Redis round-trip.
	// Require JTI for all access tokens.
	if claims.ID == "" {
		return nil, ErrInvalidToken
	}

	accountID := ""
	if claims.IssuedAt != nil && claims.AccountID != "" {
		accountID = claims.AccountID
	}

	revocation, err := s.blacklist.CheckTokenAndAccountRevocation(ctx, claims.ID, accountID)
	if err != nil {
		s.logger.Error("Failed to check token/account revocation, rejecting token", zap.Error(err), zap.String("jti", utility.MaskOpaqueID(claims.ID)))
		return nil, ErrBlacklistUnavailable
	}
	if revocation.TokenRevoked {
		return nil, ErrTokenRevoked
	}

	// Reject tokens with a not-before claim in the future beyond the configured clock skew.
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now().Add(accessTokenClockSkew)) {
		return nil, ErrInvalidToken
	}

	// Account-level revocation check — rejects all tokens issued before the
	// account's revocation timestamp (e.g., after OIDC logout).
	if !revocation.AccountRevokedAfter.IsZero() && claims.IssuedAt != nil && claims.IssuedAt.Before(revocation.AccountRevokedAfter) {
		return nil, ErrTokenRevoked
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token
func (s *TokenService) ValidateRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	key := s.buildRefreshTokenKey(token)
	data, err := s.redis.Get(ctx, key)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	var rt domain.RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token: %w", err)
	}

	// Defense-in-depth: explicit expiry check in addition to Redis TTL.
	// A zero ExpiresAt means the token is malformed — reject it rather than
	// relying solely on Redis TTL which could be misconfigured.
	if rt.ExpiresAt.IsZero() || time.Now().After(rt.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	// Account-level revocation check — rejects refresh tokens issued before the
	// account's revocation timestamp (e.g., after OIDC logout or password change).
	if rt.AccountID != "" {
		revokedAfter, err := s.blacklist.GetAccountRevokedAfter(ctx, rt.AccountID)
		if err != nil {
			s.logger.Error("Failed to check account revoked-after for refresh token, rejecting",
				zap.Error(err), zap.String("account_id", utility.MaskOpaqueID(rt.AccountID)))
			return nil, ErrBlacklistUnavailable
		}
		if !revokedAfter.IsZero() && rt.CreatedAt.Before(revokedAfter) {
			return nil, ErrTokenRevoked
		}
	}

	return &rt, nil
}

// IntrospectToken validates a token and returns its active status (RFC 7662).
// Returns (result, nil) for both active and inactive tokens.
// Returns (nil, error) only for infrastructure failures (e.g., blacklist unavailable).
func (s *TokenService) IntrospectToken(ctx context.Context, tokenString string) (map[string]any, error) {
	claims, err := s.ValidateAccessTokenWithContext(ctx, tokenString)
	if err != nil {
		if errors.Is(err, ErrBlacklistUnavailable) {
			return nil, err
		}
		return map[string]any{"active": false}, nil
	}

	result := map[string]any{
		"active":     true,
		"sub":        claims.AccountID,
		"client_id":  claims.ClientID,
		"scope":      claims.Scope,
		"token_type": "Bearer",
	}
	if len(claims.Audience) > 0 {
		result["aud"] = claims.Audience
	}
	if claims.ExpiresAt != nil {
		result["exp"] = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		result["iat"] = claims.IssuedAt.Unix()
	}
	if claims.Issuer != "" {
		result["iss"] = claims.Issuer
	}
	if claims.SessionID != "" {
		result["sid"] = claims.SessionID
	}
	if len(claims.Roles) > 0 {
		result["roles"] = claims.Roles
	}
	if claims.ID != "" {
		result["jti"] = claims.ID
	}
	return result, nil
}
