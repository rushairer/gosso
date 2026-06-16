package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/audit"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	RefreshTokenKeyPrefix   = "refresh_token:"
	SessionTokensKeyPrefix  = "session_tokens:"
	RefreshTokenLength      = 32 // 32 bytes = 64 hex chars
	MinAccountRevocationTTL = 5 * time.Minute

	// MaxShortLivedExpiry is the maximum allowed expiry for short-lived tokens.
	// Callers requesting a longer expiry will have it clamped to this value.
	MaxShortLivedExpiry = 1 * time.Hour
)

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
		IP:        audit.IPFromContext(ctx),
		UserAgent: audit.UserAgentFromContext(ctx),
		ExpiresAt: time.Now().Add(s.refreshExpiry),
		CreatedAt: time.Now(),
	}

	if rt.IP == "" {
		s.logger.Warn("Generating refresh token without IP binding; IP-based theft detection will be unavailable",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
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
		if err := s.redis.SAddWithTTL(ctx, sessionKey, tokenHash, s.refreshExpiry); err != nil {
			s.logger.Warn("Failed to index refresh token by session", zap.Error(err), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
		}
	}

	return rt, nil
}

func (s *TokenService) buildRefreshTokenKey(token string) string {
	return fmt.Sprintf("%s%s", RefreshTokenKeyPrefix, domain.HashToken(token))
}

func (s *TokenService) buildSessionTokensKey(sessionID string) string {
	return fmt.Sprintf("%s%s", SessionTokensKeyPrefix, sessionID)
}

// KeyService returns the key service (used for ID token signing, etc.)
func (s *TokenService) KeyService() *KeyService {
	return s.keySvc
}
