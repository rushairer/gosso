package service

import (
	"encoding/base64"
	"sync"

	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
)

// JWKSService OIDC JWKS service
type JWKSService struct {
	keySvc *tokenService.KeyService
	mu     sync.RWMutex
	jwks   map[string]any
}

// NewJWKSService creates a new instance of JWKSService.
// The JWKS document is pre-computed once since the key is stable for the service lifetime.
func NewJWKSService(keySvc *tokenService.KeyService) *JWKSService {
	s := &JWKSService{
		keySvc: keySvc,
	}
	s.jwks = s.buildJWKS()
	return s
}

// GetJWKS returns the JWKS document.
func (s *JWKSService) GetJWKS() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwks
}

// Reload re-computes the JWKS document from the current RSA key.
// Call this after a key rotation (e.g., via SIGHUP handler) to update the
// published key set without restarting the service.
func (s *JWKSService) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwks = s.buildJWKS()
}

// buildJWKS constructs the JWKS document from the current key material.
func (s *JWKSService) buildJWKS() map[string]any {
	pubKey := s.keySvc.PublicKey()
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(utility.BigEndianBytes(pubKey.E))

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
