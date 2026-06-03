package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
)

const (
	RefreshTokenKeyPrefix  = "refresh_token:"
	SessionTokensKeyPrefix = "session_tokens:"
	RefreshTokenLength     = 32 // 32 bytes = 64 hex chars
)

// TokenService JWT and refresh token service
type TokenService struct {
	keySvc        *KeyService
	issuer        string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	redis         *cache.RedisClient
	blacklist     *BlacklistService
	logger        *zap.Logger
}

// NewTokenService creates a new token service instance
func NewTokenService(
	keySvc *KeyService,
	issuer string,
	accessExpiry time.Duration,
	refreshExpiry time.Duration,
	redis *cache.RedisClient,
	blacklist *BlacklistService,
	logger *zap.Logger,
) *TokenService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TokenService{
		keySvc:        keySvc,
		issuer:        issuer,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		redis:         redis,
		blacklist:     blacklist,
		logger:        logger,
	}
}

// GenerateAccessToken generates a JWT access token (RS256)
func (s *TokenService) GenerateAccessToken(claims *domain.AccessTokenClaims) (string, error) {
	now := time.Now()
	if claims.ID == "" {
		claims.ID = uuid.New().String()
	}
	claims.Issuer = s.issuer
	claims.Subject = claims.AccountID
	claims.IssuedAt = jwt.NewNumericDate(now)
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(s.accessExpiry))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keySvc.KeyID()
	tokenString, err := token.SignedString(s.keySvc.PrivateKey())
	if err != nil {
		s.logger.Error("Failed to sign access token", zap.Error(err))
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return tokenString, nil
}

// AccessExpiry returns the access token expiration duration
func (s *TokenService) AccessExpiry() time.Duration {
	return s.accessExpiry
}

// ValidateAccessToken validates a JWT access token (with blacklist check, RS256 only)
func (s *TokenService) ValidateAccessToken(tokenString string) (*domain.AccessTokenClaims, error) {
	return s.ValidateAccessTokenWithContext(context.Background(), tokenString)
}

// ValidateAccessTokenWithContext validates a JWT access token using the request context
func (s *TokenService) ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*domain.AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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

	// Blacklist check — require JTI for all access tokens
	if claims.ID == "" {
		return nil, ErrInvalidToken
	}
	revoked, err := s.blacklist.IsTokenRevoked(ctx, claims.ID)
	if err != nil {
		s.logger.Error("Failed to check token blacklist, rejecting token", zap.Error(err), zap.String("jti", claims.ID))
		return nil, ErrBlacklistUnavailable
	}
	if revoked {
		return nil, ErrTokenRevoked
	}

	return claims, nil
}

// GenerateRefreshToken generates a random refresh token and stores it in Redis
func (s *TokenService) GenerateRefreshToken(ctx context.Context, accountID, clientID, sessionID, scope string) (*domain.RefreshToken, error) {
	bytes := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		s.logger.Error("Failed to generate random bytes", zap.Error(err))
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	tokenString := hex.EncodeToString(bytes)

	rt := &domain.RefreshToken{
		Token:     tokenString,
		AccountID: accountID,
		ClientID:  clientID,
		SessionID: sessionID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.refreshExpiry),
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(rt)
	if err != nil {
		return nil, fmt.Errorf("marshal refresh token: %w", err)
	}

	key := s.buildRefreshTokenKey(tokenString)
	if err := s.redis.Set(ctx, key, data, s.refreshExpiry); err != nil {
		s.logger.Error("Failed to store refresh token", zap.Error(err))
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	// Maintain session -> tokens index
	if sessionID != "" {
		sessionKey := s.buildSessionTokensKey(sessionID)
		tokenHash := domain.HashToken(tokenString)
		if err := s.redis.SAdd(ctx, sessionKey, tokenHash); err != nil {
			s.logger.Warn("Failed to index refresh token by session", zap.Error(err), zap.String("session_id", sessionID))
		}
		_ = s.redis.Expire(ctx, sessionKey, s.refreshExpiry)
	}

	return rt, nil
}

// ValidateRefreshToken validates a refresh token
func (s *TokenService) ValidateRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	key := s.buildRefreshTokenKey(token)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	var rt domain.RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token: %w", err)
	}

	return &rt, nil
}

// rotateAndDeleteScript atomically retrieves and deletes a refresh token in a single Redis operation.
// Returns the token data if it existed (and was deleted), or nil if it was already consumed.
// This prevents TOCTOU race conditions during refresh token rotation.
var rotateAndDeleteScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if data then
    redis.call('DEL', KEYS[1])
end
return data
`)

// rotateTokenScript atomically rotates a refresh token: validates and deletes the old token,
// stores the new token with real data, and updates the session index — all in a single Lua script.
// KEYS[1] = old token key, KEYS[2] = new token key, KEYS[3] = session index key (or "" if no session)
// ARGV[1] = new token JSON, ARGV[2] = expiry seconds, ARGV[3] = old token hash, ARGV[4] = new token hash
// Returns old token data on success, nil if old token not found.
var rotateTokenScript = redis.NewScript(`
local oldData = redis.call('GET', KEYS[1])
if not oldData then
    return nil
end
redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
if KEYS[3] ~= '' then
    redis.call('SREM', KEYS[3], ARGV[3])
    redis.call('SADD', KEYS[3], ARGV[4])
    redis.call('EXPIRE', KEYS[3], ARGV[2])
end
return oldData
`)

// RotateRefreshToken rotates refresh tokens atomically.
// The old token is read (read-only), validated, and replaced with a new token in a single Lua script.
// The new token data is passed directly to the Lua script, eliminating any placeholder/overwrite window.
func (s *TokenService) RotateRefreshToken(ctx context.Context, oldToken string) (*domain.RefreshToken, error) {
	// 1. Read old token data (read-only) to derive new token fields
	oldKey := s.buildRefreshTokenKey(oldToken)
	oldDataStr, err := s.redis.Get(ctx, oldKey)
	if err == cache.ErrKeyNotFound {
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	var oldRT domain.RefreshToken
	if err := json.Unmarshal([]byte(oldDataStr), &oldRT); err != nil {
		return nil, fmt.Errorf("unmarshal old refresh token: %w", err)
	}

	// 2. Generate new token and build complete data
	newBytes := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(newBytes); err != nil {
		return nil, fmt.Errorf("generate new token: %w", err)
	}
	newTokenString := hex.EncodeToString(newBytes)

	newRT := &domain.RefreshToken{
		Token:     newTokenString,
		AccountID: oldRT.AccountID,
		ClientID:  oldRT.ClientID,
		SessionID: oldRT.SessionID,
		Scope:     oldRT.Scope,
		ExpiresAt: time.Now().Add(s.refreshExpiry),
		CreatedAt: time.Now(),
	}

	newData, err := json.Marshal(newRT)
	if err != nil {
		return nil, fmt.Errorf("marshal new refresh token: %w", err)
	}

	// 3. Atomically rotate: delete old, store new (with real data), update session index
	newHash := domain.HashToken(newTokenString)
	oldHash := domain.HashToken(oldToken)
	newKey := s.buildRefreshTokenKey(newTokenString)
	expirySeconds := int(s.refreshExpiry.Seconds())

	sessionKey := ""
	if newRT.SessionID != "" {
		sessionKey = s.buildSessionTokensKey(newRT.SessionID)
	}

	result, err := rotateTokenScript.Run(ctx, s.redis.GetClient(),
		[]string{oldKey, newKey, sessionKey},
		newData, expirySeconds, oldHash, newHash,
	).Result()
	if err == redis.Nil || result == nil {
		return nil, fmt.Errorf("refresh token not found or expired: %w", cache.ErrKeyNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	return newRT, nil
}

// RevokeRefreshToken revokes a refresh token and removes it from the session index.
func (s *TokenService) RevokeRefreshToken(ctx context.Context, token string) error {
	key := s.buildRefreshTokenKey(token)

	data, err := rotateAndDeleteScript.Run(ctx, s.redis.GetClient(), []string{key}).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	// Clean up session index
	if dataStr, ok := data.(string); ok && dataStr != "" {
		var rt domain.RefreshToken
		if jsonErr := json.Unmarshal([]byte(dataStr), &rt); jsonErr == nil && rt.SessionID != "" {
			sessionKey := s.buildSessionTokensKey(rt.SessionID)
			tokenHash := domain.HashToken(token)
			_ = s.redis.SRem(ctx, sessionKey, tokenHash)
		}
	}

	return nil
}

// RevokeAllForSession revokes all refresh tokens under a given session
func (s *TokenService) RevokeAllForSession(ctx context.Context, sessionID string) error {
	sessionKey := s.buildSessionTokensKey(sessionID)

	hashes, err := s.redis.SMembers(ctx, sessionKey)
	if err != nil {
		return fmt.Errorf("get session tokens: %w", err)
	}

	// Delete the session index FIRST, then delete individual tokens.
	// If individual deletion partially fails, tokens will expire naturally via TTL.
	// Deleting the index first prevents orphaned tokens from being discoverable.
	if err := s.redis.Del(ctx, sessionKey); err != nil {
		s.logger.Warn("Failed to delete session tokens set", zap.String("session_id", sessionID), zap.Error(err))
	}

	if len(hashes) > 0 {
		keys := make([]string, len(hashes))
		for i, hash := range hashes {
			keys[i] = RefreshTokenKeyPrefix + hash
		}
		if err := s.redis.Del(ctx, keys...); err != nil {
			s.logger.Warn("Failed to delete refresh tokens during session revoke",
				zap.String("session_id", sessionID), zap.Error(err))
		}
	}

	s.logger.Info("Revoked all refresh tokens for session",
		zap.String("session_id", sessionID), zap.Int("count", len(hashes)))
	return nil
}

// RevokeAccessToken blacklists an access token by its JTI so it can no longer be used.
func (s *TokenService) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	if s.blacklist == nil {
		s.logger.Warn("RevokeAccessToken called but blacklist is nil, token not revoked", zap.String("jti", jti))
		return nil
	}
	return s.blacklist.RevokeToken(ctx, jti, "logout", expiresAt)
}

func (s *TokenService) buildRefreshTokenKey(token string) string {
	return fmt.Sprintf("%s%s", RefreshTokenKeyPrefix, domain.HashToken(token))
}

func (s *TokenService) buildSessionTokensKey(sessionID string) string {
	return fmt.Sprintf("%s%s", SessionTokensKeyPrefix, sessionID)
}

// IntrospectToken validates a token and returns its active status (RFC 7662).
// Returns (result, nil) for both active and inactive tokens.
// Returns (nil, error) only for infrastructure failures (e.g., blacklist unavailable).
func (s *TokenService) IntrospectToken(ctx context.Context, tokenString string) (map[string]any, error) {
	claims, err := s.ValidateAccessTokenWithContext(ctx, tokenString)
	if err != nil {
		if err == ErrBlacklistUnavailable {
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
	return result, nil
}

// KeyService returns the key service (used for ID token signing, etc.)
func (s *TokenService) KeyService() *KeyService {
	return s.keySvc
}
