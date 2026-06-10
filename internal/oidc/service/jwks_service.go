package service

import (
	"encoding/base64"

	tokenService "github.com/rushairer/gosso/internal/token/service"
)

// JWKSService OIDC JWKS service
type JWKSService struct {
	jwks map[string]any
}

// NewJWKSService creates a new instance of JWKSService.
// The JWKS document is pre-computed once since the key is stable for the service lifetime.
func NewJWKSService(keySvc *tokenService.KeyService) *JWKSService {
	pubKey := keySvc.PublicKey()
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(tokenService.BigEndianBytes(pubKey.E))

	return &JWKSService{
		jwks: map[string]any{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"kid": keySvc.KeyID(),
					"alg": "RS256",
					"use": "sig",
					"n":   n,
					"e":   e,
				},
			},
		},
	}
}

// GetJWKS returns the JWKS document (pre-computed, immutable)
func (s *JWKSService) GetJWKS() map[string]any {
	return s.jwks
}
