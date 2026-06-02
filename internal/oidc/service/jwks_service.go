package service

import (
	"encoding/base64"

	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// JWKSService OIDC JWKS service
type JWKSService struct {
	keySvc *tokenService.KeyService
}

// NewJWKSService creates a new instance of JWKSService
func NewJWKSService(keySvc *tokenService.KeyService) *JWKSService {
	return &JWKSService{keySvc: keySvc}
}

// GetJWKS returns the JWKS document (RSA public key)
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
