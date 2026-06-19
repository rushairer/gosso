package service

import (
	"encoding/base64"
	"sync"

	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
)

// JWKSService OIDC JWKS service
type JWKSService struct {
	keySvc      *tokenService.KeyService
	mu          sync.RWMutex
	jwks        map[string]any
	previousKey *map[string]string // previous key for rotation overlap, nil if none
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
//
// The previous key is retained and published alongside the new key during
// the rotation window. Call ClearPreviousKey() after the old key's
// longest-lived token has expired to remove it from the JWKS.
func (s *JWKSService) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Save current key as previous before replacing
	currentKey := s.buildCurrentKeyEntry()
	s.previousKey = &currentKey
	s.jwks = s.buildJWKS()
}

// ClearPreviousKey removes the previous key from the JWKS document.
// Call this after the old key's longest-lived token has expired.
func (s *JWKSService) ClearPreviousKey() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previousKey = nil
	s.jwks = s.buildJWKS()
}

// buildCurrentKeyEntry builds a single key entry from the current key service.
func (s *JWKSService) buildCurrentKeyEntry() map[string]string {
	pubKey := s.keySvc.PublicKey()
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(utility.BigEndianBytes(pubKey.E))
	return map[string]string{
		"kty": "RSA",
		"kid": s.keySvc.KeyID(),
		"alg": "RS256",
		"use": "sig",
		"n":   n,
		"e":   e,
	}
}

// buildJWKS constructs the JWKS document from the current key material,
// including the previous key if one exists (for rotation overlap).
func (s *JWKSService) buildJWKS() map[string]any {
	keys := []map[string]string{s.buildCurrentKeyEntry()}
	if s.previousKey != nil {
		keys = append(keys, *s.previousKey)
	}
	return map[string]any{
		"keys": keys,
	}
}
