package service

import (
	"encoding/base64"

	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// JWKSService OIDC JWKS 服务
type JWKSService struct {
	keySvc *tokenService.KeyService
}

// NewJWKSService 创建 JWKS 服务实例
func NewJWKSService(keySvc *tokenService.KeyService) *JWKSService {
	return &JWKSService{keySvc: keySvc}
}

// GetJWKS 返回 JWKS 文档（RSA 公钥）
func (s *JWKSService) GetJWKS() map[string]any {
	pubKey := s.keySvc.PublicKey()
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(tokenService.BigEndianBytes(pubKey.E))

	return map[string]any{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"kid": s.keySvc.KeyID(),
				"alg": "RS256",
				"use": "sig",
				"n":   n,
				"e":   e,
			},
		},
	}
}
