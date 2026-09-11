package service

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
)

// JWKSService publishes the active signing key plus all retained public keys
// from KeyService. The cached document is refreshed lazily when the key-ring
// revision changes.
type JWKSService struct {
	keySvc   *tokenService.KeyService
	mu       sync.RWMutex
	jwksJSON []byte
	revision uint64
}

// NewJWKSService creates a new instance of JWKSService.
func NewJWKSService(keySvc *tokenService.KeyService) *JWKSService {
	s := &JWKSService{keySvc: keySvc}
	s.reloadLocked()
	return s
}

// GetJWKS returns the pre-marshaled JWKS JSON bytes, refreshing automatically
// after a signing-key activation/retirement.
func (s *JWKSService) GetJWKS() []byte {
	s.ensureFresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwksJSON
}

func (s *JWKSService) ensureFresh() {
	revision := s.keySvc.Revision()
	s.mu.RLock()
	fresh := s.revision == revision
	s.mu.RUnlock()
	if fresh {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision != s.keySvc.Revision() {
		s.reloadLocked()
	}
}

// GetPublicKeyByKID returns the active or retained RSA public key matching kid.
func (s *JWKSService) GetPublicKeyByKID(kid string) (*rsa.PublicKey, error) {
	return s.keySvc.PublicKeyByKID(kid)
}

// GetAllPublicKeys returns all RSA public keys currently available for
// verification (active + retained historical keys).
func (s *JWKSService) GetAllPublicKeys() []*rsa.PublicKey {
	keysByID := s.keySvc.AllPublicKeys()
	kids := make([]string, 0, len(keysByID))
	for kid := range keysByID {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	keys := make([]*rsa.PublicKey, 0, len(kids))
	for _, kid := range kids {
		keys = append(keys, keysByID[kid])
	}
	return keys
}

// Reload forces a JWKS cache rebuild from the current KeyService key ring. It
// does not rotate key material; activation is performed by KeyService.ActivateKey.
func (s *JWKSService) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked()
}

// ClearPreviousKey removes retained historical verification keys and rebuilds
// the JWKS document. Retire individual keys through KeyService.RetireKey when a
// targeted retirement is preferred.
func (s *JWKSService) ClearPreviousKey() {
	s.keySvc.ClearPreviousKeys()
	s.Reload()
}

func (s *JWKSService) reloadLocked() {
	s.jwksJSON = s.marshalJWKS()
	s.revision = s.keySvc.Revision()
}

func buildKeyEntry(kid string, pubKey *rsa.PublicKey) map[string]string {
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	eBytes, err := utility.BigEndianBytes(pubKey.E)
	if err != nil {
		panic("jwks: unexpected BigEndianBytes error: " + err.Error())
	}
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   n,
		"e":   e,
	}
}

// marshalJWKS constructs a deterministic JWKS document from the active and
// retained public-key ring.
func (s *JWKSService) marshalJWKS() []byte {
	keysByID := s.keySvc.AllPublicKeys()
	kids := make([]string, 0, len(keysByID))
	for kid := range keysByID {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	keys := make([]map[string]string, 0, len(kids))
	for _, kid := range kids {
		pubKey := keysByID[kid]
		if pubKey == nil {
			continue
		}
		keys = append(keys, buildKeyEntry(kid, pubKey))
	}
	if len(keys) == 0 {
		panic("jwks: signing key ring is empty")
	}
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(fmt.Sprintf("jwks: marshal error: %v", err))
	}
	return b
}
