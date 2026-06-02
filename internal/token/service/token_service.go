package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/token/domain"
)

const (
	RefreshTokenKeyPrefix  = "refresh_token:"
	SessionTokensKeyPrefix = "session_tokens:"
	RefreshTokenLength     = 32 // 32 bytes = 64 hex chars
)

// TokenService JWT 和刷新令牌服务
type TokenService struct {
	secret        []byte
	keySvc        *KeyService
	issuer        string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	redis         *cache.RedisClient
	blacklist     *BlacklistService
	logger        *zap.Logger
}

// NewTokenService 创建 Token 服务实例
func NewTokenService(
	secret []byte,
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
		secret:        secret,
		keySvc:        keySvc,
		issuer:        issuer,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		redis:         redis,
		blacklist:     blacklist,
		logger:        logger,
	}
}

// GenerateAccessToken 生成 JWT Access Token (RS256)
func (s *TokenService) GenerateAccessToken(claims *domain.AccessTokenClaims) (string, error) {
	now := time.Now()
	claims.Issuer = s.issuer
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(s.accessExpiry))

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keySvc.KeyID()
	tokenString, err := token.SignedString(s.keySvc.PrivateKey())
	if err != nil {
		s.logger.Error("Failed to sign access token", zap.Error(err))
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return tokenString, nil
}

// AccessExpiry 返回 access token 过期时间
func (s *TokenService) AccessExpiry() time.Duration {
	return s.accessExpiry
}

// ValidateAccessToken 验证 JWT Access Token（含黑名单检查，支持 RS256 + HS256 回退）
func (s *TokenService) ValidateAccessToken(tokenString string) (*domain.AccessTokenClaims, error) {
	return s.ValidateAccessTokenWithContext(context.Background(), tokenString)
}

// ValidateAccessTokenWithContext 使用请求 context 验证 JWT Access Token
func (s *TokenService) ValidateAccessTokenWithContext(ctx context.Context, tokenString string) (*domain.AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			return s.keySvc.PublicKey(), nil
		case *jwt.SigningMethodHMAC:
			if len(s.secret) > 0 {
				return s.secret, nil
			}
			return nil, fmt.Errorf("HS256 secret not configured for fallback validation")
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}

	claims, ok := token.Claims.(*domain.AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// 黑名单检查
	if claims.ID != "" {
		revoked, err := s.blacklist.IsTokenRevoked(ctx, claims.ID)
		if err != nil {
			s.logger.Warn("Failed to check token blacklist", zap.Error(err), zap.String("jti", claims.ID))
		}
		if revoked {
			return nil, ErrTokenRevoked
		}
	}

	return claims, nil
}

// GenerateRefreshToken 生成随机刷新令牌并存储到 Redis
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

	// 维护 session → tokens 索引
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

// ValidateRefreshToken 验证刷新令牌
func (s *TokenService) ValidateRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	key := s.buildRefreshTokenKey(token)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
		return nil, fmt.Errorf("refresh token not found or expired")
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

// RotateRefreshToken 刷新令牌轮转：删除旧令牌，生成新令牌
func (s *TokenService) RotateRefreshToken(ctx context.Context, oldToken string) (*domain.RefreshToken, error) {
	rt, err := s.ValidateRefreshToken(ctx, oldToken)
	if err != nil {
		return nil, err
	}

	// 删除旧令牌
	oldKey := s.buildRefreshTokenKey(oldToken)
	if err := s.redis.Del(ctx, oldKey); err != nil {
		s.logger.Warn("Failed to delete old refresh token", zap.Error(err))
	}

	// 从 session 索引中移除旧 hash
	if rt.SessionID != "" {
		sessionKey := s.buildSessionTokensKey(rt.SessionID)
		oldHash := domain.HashToken(oldToken)
		if err := s.redis.SRem(ctx, sessionKey, oldHash); err != nil {
			s.logger.Warn("Failed to remove old token from session index", zap.Error(err))
		}
	}

	// 生成新令牌（GenerateRefreshToken 会自动加入 session 索引）
	newRT, err := s.GenerateRefreshToken(ctx, rt.AccountID, rt.ClientID, rt.SessionID, rt.Scope)
	if err != nil {
		return nil, err
	}

	return newRT, nil
}

// RevokeRefreshToken 撤销刷新令牌
func (s *TokenService) RevokeRefreshToken(ctx context.Context, token string) error {
	key := s.buildRefreshTokenKey(token)
	if err := s.redis.Del(ctx, key); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

// RevokeAllForSession 撤销某个会话下的所有刷新令牌
func (s *TokenService) RevokeAllForSession(ctx context.Context, sessionID string) error {
	sessionKey := s.buildSessionTokensKey(sessionID)

	hashes, err := s.redis.SMembers(ctx, sessionKey)
	if err != nil {
		return fmt.Errorf("get session tokens: %w", err)
	}

	// 删除每个 refresh token
	for _, hash := range hashes {
		tokenKey := RefreshTokenKeyPrefix + hash
		if err := s.redis.Del(ctx, tokenKey); err != nil {
			s.logger.Warn("Failed to delete refresh token during session revoke",
				zap.String("session_id", sessionID), zap.String("hash", hash), zap.Error(err))
		}
	}

	// 删除 session 索引
	if err := s.redis.Del(ctx, sessionKey); err != nil {
		s.logger.Warn("Failed to delete session tokens set", zap.String("session_id", sessionID), zap.Error(err))
	}

	s.logger.Info("Revoked all refresh tokens for session",
		zap.String("session_id", sessionID), zap.Int("count", len(hashes)))
	return nil
}

func (s *TokenService) buildRefreshTokenKey(token string) string {
	return fmt.Sprintf("%s%s", RefreshTokenKeyPrefix, domain.HashToken(token))
}

func (s *TokenService) buildSessionTokensKey(sessionID string) string {
	return fmt.Sprintf("%s%s", SessionTokensKeyPrefix, sessionID)
}

// IntrospectToken 验证 token 并返回活跃状态（RFC 7662）
func (s *TokenService) IntrospectToken(ctx context.Context, tokenString string) (map[string]any, error) {
	claims, err := s.ValidateAccessToken(tokenString)
	if err != nil {
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

// KeyService 返回密钥服务（供 ID Token 等签发使用）
func (s *TokenService) KeyService() *KeyService {
	return s.keySvc
}
