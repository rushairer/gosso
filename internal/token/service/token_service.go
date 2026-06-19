package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/audit"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	refreshTokenKeyPrefix   = "refresh_token:"
	sessionTokensKeyPrefix  = "session_tokens:"
	refreshTokenLength      = 32 // 32 bytes = 64 hex chars
	MinAccountRevocationTTL = 5 * time.Minute

	// MaxShortLivedExpiry is the maximum allowed expiry for short-lived tokens.
	// Callers requesting a longer expiry will have it clamped to this value.
	MaxShortLivedExpiry = 1 * time.Hour
)

// storeRefreshTokenScript atomically stores a refresh token and updates the session→tokens index.
var storeRefreshTokenScript = redis.NewScript(`
	redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
	if KEYS[2] ~= '' then
		redis.call('SADD', KEYS[2], ARGV[3])
		redis.call('EXPIRE', KEYS[2], ARGV[2])
	end
	return 1
`)

// TokenService JWT and refresh token service
type TokenService struct {
	keySvc        *KeyService
	issuer        string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	redis         *cache.RedisClient
	blacklist     *BlacklistService
	auditor       *auditService.Auditor
	logger        *zap.Logger
}

// NewTokenService creates a new token service instance.
// Returns an error if keySvc or redis is nil.
func NewTokenService(
	keySvc *KeyService,
	issuer string,
	accessExpiry time.Duration,
	refreshExpiry time.Duration,
	redis *cache.RedisClient,
	blacklist *BlacklistService,
	auditor *auditService.Auditor,
	logger *zap.Logger,
) (*TokenService, error) {
	logger = utility.EnsureLogger(logger)
	if keySvc == nil {
		return nil, errors.New("token service: keySvc is required")
	}
	if redis == nil {
		return nil, errors.New("token service: redis client is required")
	}
	if blacklist == nil {
		return nil, errors.New("token service: blacklist service is required")
	}
	// auditor is optional — audit logging is best-effort and nil-safe.
	if accessExpiry <= 0 {
		return nil, errors.New("token service: accessExpiry must be positive")
	}
	if refreshExpiry <= 0 {
		return nil, errors.New("token service: refreshExpiry must be positive")
	}
	return &TokenService{
		keySvc:        keySvc,
		issuer:        issuer,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		redis:         redis,
		blacklist:     blacklist,
		auditor:       auditor,
		logger:        logger,
	}, nil
}

// GenerateAccessToken generates a JWT access token (RS256)
func (s *TokenService) GenerateAccessToken(claims *domain.AccessTokenClaims) (string, error) {
	now := time.Now()
	clonedClaims := *claims
	if clonedClaims.ID == "" {
		clonedClaims.ID = uuid.New().String()
	}
	clonedClaims.Issuer = s.issuer
	clonedClaims.Subject = clonedClaims.AccountID
	clonedClaims.IssuedAt = jwt.NewNumericDate(now)
	clonedClaims.ExpiresAt = jwt.NewNumericDate(now.Add(s.accessExpiry))

	return s.signToken(&clonedClaims, "access token")
}

// GenerateShortLivedToken generates a JWT access token (RS256) that respects
// the caller-provided ExpiresAt. Unlike GenerateAccessToken which always uses
// the configured accessExpiry, this method preserves short TTLs for special
// purposes like MFA verification tokens.
func (s *TokenService) GenerateShortLivedToken(claims *domain.AccessTokenClaims) (string, error) {
	now := time.Now()
	clonedClaims := *claims
	if clonedClaims.ID == "" {
		clonedClaims.ID = uuid.New().String()
	}
	clonedClaims.Issuer = s.issuer
	clonedClaims.Subject = clonedClaims.AccountID
	clonedClaims.IssuedAt = jwt.NewNumericDate(now)
	if clonedClaims.ExpiresAt == nil || clonedClaims.ExpiresAt.IsZero() {
		clonedClaims.ExpiresAt = jwt.NewNumericDate(now.Add(s.accessExpiry))
	}

	// Enforce maximum TTL for short-lived tokens to prevent callers from
	// accidentally requesting excessively long-lived tokens.
	maxExpiry := jwt.NewNumericDate(now.Add(MaxShortLivedExpiry))
	if clonedClaims.ExpiresAt.After(maxExpiry.Time) {
		s.logger.Warn("Short-lived token expiry clamped to maximum",
			zap.Duration("requested", time.Until(clonedClaims.ExpiresAt.Time)),
			zap.Duration("max", MaxShortLivedExpiry))
		clonedClaims.ExpiresAt = maxExpiry
	}

	return s.signToken(&clonedClaims, "short-lived token")
}

// signToken creates and signs a JWT with RS256, setting the kid header.
func (s *TokenService) signToken(claims *domain.AccessTokenClaims, label string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keySvc.KeyID()
	tokenString, err := token.SignedString(s.keySvc.PrivateKey())
	if err != nil {
		s.logger.Error("Failed to sign "+label, zap.Error(err))
		return "", fmt.Errorf("sign %s: %w", label, err)
	}
	return tokenString, nil
}

// AccessExpiry returns the access token expiration duration
func (s *TokenService) AccessExpiry() time.Duration {
	return s.accessExpiry
}

// GenerateRefreshToken generates a random refresh token and stores it in Redis
func (s *TokenService) GenerateRefreshToken(ctx context.Context, accountID, clientID, sessionID, scope string) (*domain.RefreshToken, error) {
	bytes := make([]byte, refreshTokenLength)
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
		IP:        audit.IPFromContext(ctx),
		UserAgent: audit.UserAgentFromContext(ctx),
	}
	now := time.Now()
	rt.ExpiresAt = now.Add(s.refreshExpiry)
	rt.CreatedAt = now

	if rt.IP == "" {
		s.logger.Warn("Generating refresh token without IP binding; IP-based theft detection will be unavailable",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
	}

	data, err := json.Marshal(rt)
	if err != nil {
		return nil, fmt.Errorf("marshal refresh token: %w", err)
	}

	key := s.buildRefreshTokenKey(tokenString)
	ttlSecs := int(math.Ceil(s.refreshExpiry.Seconds()))
	if ttlSecs < 1 {
		ttlSecs = 1
	}

	// Atomically store the refresh token and update the session -> tokens index
	// in a single Lua script to prevent partial state on crash.
	sessionKey := ""
	if sessionID != "" {
		sessionKey = s.buildSessionTokensKey(sessionID)
	}
	tokenHash := domain.HashToken(tokenString)
	if err := s.redis.RunScript(ctx, storeRefreshTokenScript,
		[]string{key, sessionKey}, data, ttlSecs, tokenHash,
		).Err(); err != nil {
		s.logger.Error("Failed to store refresh token (atomic)", zap.Error(err))
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return rt, nil
}

func (s *TokenService) buildRefreshTokenKey(token string) string {
	return fmt.Sprintf("%s%s", refreshTokenKeyPrefix, domain.HashToken(token))
}

func (s *TokenService) buildSessionTokensKey(sessionID string) string {
	return fmt.Sprintf("%s%s", sessionTokensKeyPrefix, sessionID)
}

// KeyService returns the underlying key service.
// Exposed for OIDC JWKS endpoint (public key distribution) and ID token signing.
// Callers should not use this to sign arbitrary tokens — use TokenService methods instead.
func (s *TokenService) KeyService() *KeyService {
	return s.keySvc
}
