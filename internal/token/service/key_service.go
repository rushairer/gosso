package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/utility"
)

const defaultRSAKeyBits = 3072

const (
	previousPublicKeyPathEnv = "GOUNO_AUTH_PREVIOUS_PUBLIC_KEY_PATH"
	previousKeyIDEnv         = "GOUNO_AUTH_PREVIOUS_KEY_ID"
)

// KeyService manages the active RSA signing key and retained public keys used
// to verify tokens issued before a rotation. Private key material is kept only
// for the active key; historical entries contain public keys only.
type KeyService struct {
	mu           sync.RWMutex
	privateKey   *rsa.PrivateKey
	keyID        string
	previousKeys map[string]*rsa.PublicKey
	revision     atomic.Uint64
	logger       *zap.Logger
}

// NewKeyService creates a KeyService. Loading/generation strategy:
//  1. privateKeyPath non-empty and file exists → load from PEM
//  2. privateKeyPath non-empty and file missing:
//     - isProduction = true → return error (do not auto-generate new key)
//     - isProduction = false → generate and write PEM
//  3. privateKeyPath empty → generate in-memory (dev mode, keys lost on restart)
//
// keyBits specifies the RSA key size for new key generation. If 0, defaults to 3072.
// Returns an error if keyBits is non-zero and less than 2048.
//
// A retained public key can be supplied during rolling key rotation through
// GOUNO_AUTH_PREVIOUS_PUBLIC_KEY_PATH + GOUNO_AUTH_PREVIOUS_KEY_ID. Both must
// be set together. This keeps verification/JWKS overlap durable across process
// restarts without retaining the old private key.
func NewKeyService(privateKeyPath string, keyID string, isProduction bool, keyBits int, logger *zap.Logger) (*KeyService, error) {
	if keyBits == 0 {
		keyBits = defaultRSAKeyBits
	}
	if keyBits < 2048 {
		return nil, fmt.Errorf("rsa_key_bits must be at least 2048 (got %d)", keyBits)
	}

	logger = utility.EnsureLogger(logger)

	var privateKey *rsa.PrivateKey
	var err error

	if privateKeyPath != "" {
		if info, statErr := os.Stat(privateKeyPath); statErr == nil {
			// Reject or warn if key file has overly permissive permissions
			if info.Mode().Perm()&0077 != 0 {
				if isProduction {
					return nil, fmt.Errorf("RSA private key file %s has overly permissive permissions %s; expected 0600 (hint: chmod 600 %s)", privateKeyPath, info.Mode().Perm(), privateKeyPath)
				}
				logger.Warn("RSA private key file has overly permissive permissions",
					zap.String("path", privateKeyPath),
					zap.String("mode", info.Mode().Perm().String()),
					zap.String("hint", "chmod 600 "+privateKeyPath))
			}
			privateKey, err = loadPrivateKeyFromPEM(privateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("load private key: %w", err)
			}
			logger.Info("RSA private key loaded from file", zap.String("path", privateKeyPath))
		} else {
			if isProduction {
				return nil, fmt.Errorf("RSA private key file not found at %s in production mode", privateKeyPath)
			}
			privateKey, err = generateAndSaveKey(privateKeyPath, keyBits)
			if err != nil {
				return nil, fmt.Errorf("generate and save key: %w", err)
			}
			logger.Error("!!! RSA private key file not found — generating NEW key. All previously issued tokens will be INVALID. !!!",
				zap.String("path", privateKeyPath))
			logger.Error("!!! This should NEVER happen in production. Ensure private_key_path is correctly configured. !!!")
		}
	} else {
		privateKey, err = generateKey(keyBits)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		logger.Info("RSA private key generated in memory (dev mode)")
	}

	kid := keyID
	if kid == "" {
		computedKid, err := computeKeyID(&privateKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("compute key ID: %w", err)
		}
		kid = computedKid
	}

	s := &KeyService{
		privateKey:   privateKey,
		keyID:        kid,
		previousKeys: make(map[string]*rsa.PublicKey),
		logger:       logger,
	}
	s.revision.Store(1)

	previousPath := os.Getenv(previousPublicKeyPathEnv)
	previousID := os.Getenv(previousKeyIDEnv)
	if (previousPath == "") != (previousID == "") {
		return nil, fmt.Errorf("%s and %s must be configured together", previousPublicKeyPathEnv, previousKeyIDEnv)
	}
	if previousPath != "" {
		if err := s.LoadPreviousPublicKey(previousPath, previousID); err != nil {
			return nil, fmt.Errorf("load retained signing public key: %w", err)
		}
	}

	return s, nil
}

// SigningKey returns the active private key and kid from one consistent
// snapshot, preventing a rotation between header construction and signing.
func (s *KeyService) SigningKey() (*rsa.PrivateKey, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.privateKey, s.keyID
}

func (s *KeyService) PrivateKey() *rsa.PrivateKey {
	key, _ := s.SigningKey()
	return key
}

func (s *KeyService) PublicKey() *rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.privateKey == nil {
		return nil
	}
	return &s.privateKey.PublicKey
}

func (s *KeyService) KeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyID
}

// Revision changes whenever the active or retained verification-key set
// changes. JWKSService uses it to refresh its cached document lazily.
func (s *KeyService) Revision() uint64 {
	return s.revision.Load()
}

// PublicKeyByKID returns a verification key for the active or retained kid.
// An empty kid is treated as the active key for compatibility with historical
// JWTs that did not carry a kid header.
func (s *KeyService) PublicKeyByKID(kid string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if kid == "" || kid == s.keyID {
		if s.privateKey == nil {
			return nil, errors.New("active signing key is unavailable")
		}
		return &s.privateKey.PublicKey, nil
	}
	if key, ok := s.previousKeys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("no signing public key found for kid %q", kid)
}

// AllPublicKeys returns a snapshot of active + retained verification keys.
func (s *KeyService) AllPublicKeys() map[string]*rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make(map[string]*rsa.PublicKey, len(s.previousKeys)+1)
	if s.privateKey != nil {
		keys[s.keyID] = &s.privateKey.PublicKey
	}
	for kid, key := range s.previousKeys {
		keys[kid] = key
	}
	return keys
}

// LoadPreviousPublicKey retains a historical public key for token verification
// and JWKS overlap. The active kid cannot be reused for different material.
func (s *KeyService) LoadPreviousPublicKey(path, kid string) error {
	if path == "" || kid == "" {
		return errors.New("previous public key path and kid are required")
	}
	key, err := loadPublicKeyFromPEM(path)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if kid == s.keyID {
		if s.privateKey != nil && publicKeysEqual(key, &s.privateKey.PublicKey) {
			return nil
		}
		return fmt.Errorf("retained key kid %q conflicts with active signing key", kid)
	}
	s.previousKeys[kid] = key
	s.revision.Add(1)
	s.logger.Info("Retained previous RSA public key for rotation overlap", zap.String("kid", kid), zap.String("path", path))
	return nil
}

// ActivateKey atomically switches signing to the private key at path. The old
// active public key is retained automatically so already-issued tokens remain
// verifiable. Pass an empty newKeyID to derive a stable ID from the new key.
func (s *KeyService) ActivateKey(path, newKeyID string) error {
	if path == "" {
		return errors.New("activation private key path is required")
	}
	newPrivate, err := loadPrivateKeyFromPEM(path)
	if err != nil {
		return fmt.Errorf("load activation private key: %w", err)
	}
	if newKeyID == "" {
		newKeyID, err = computeKeyID(&newPrivate.PublicKey)
		if err != nil {
			return fmt.Errorf("compute activation key ID: %w", err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if newKeyID == s.keyID {
		if s.privateKey != nil && publicKeysEqual(&newPrivate.PublicKey, &s.privateKey.PublicKey) {
			return nil
		}
		return fmt.Errorf("new key material cannot reuse active kid %q", newKeyID)
	}
	if _, exists := s.previousKeys[newKeyID]; exists {
		return fmt.Errorf("new active kid %q already exists in retained key ring", newKeyID)
	}
	if s.privateKey != nil && s.keyID != "" {
		s.previousKeys[s.keyID] = &s.privateKey.PublicKey
	}
	s.privateKey = newPrivate
	s.keyID = newKeyID
	s.revision.Add(1)
	s.logger.Info("Activated new RSA signing key", zap.String("kid", newKeyID))
	return nil
}

// RetireKey removes a historical verification key. The active key cannot be
// retired through this method.
func (s *KeyService) RetireKey(kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kid == "" {
		return errors.New("kid is required")
	}
	if kid == s.keyID {
		return errors.New("cannot retire active signing key")
	}
	if _, ok := s.previousKeys[kid]; !ok {
		return fmt.Errorf("retained signing key %q not found", kid)
	}
	delete(s.previousKeys, kid)
	s.revision.Add(1)
	return nil
}

// ClearPreviousKeys removes all historical verification keys.
func (s *KeyService) ClearPreviousKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.previousKeys) == 0 {
		return
	}
	s.previousKeys = make(map[string]*rsa.PublicKey)
	s.revision.Add(1)
}

func generateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func generateAndSaveKey(path string, bits int) (*rsa.PrivateKey, error) {
	key, err := generateKey(bits)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}

	if err := savePrivateKeyToPEM(path, key); err != nil {
		return nil, err
	}

	return key, nil
}

func savePrivateKeyToPEM(path string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal PKCS8: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".private-key-*.pem.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath) // cleanup on failure
	}()

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}

	if err := pem.Encode(tmp, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode PEM: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

func loadPrivateKeyFromPEM(path string) (*rsa.PrivateKey, error) {
	// #nosec G703 -- signing-key paths are operator-controlled deployment configuration, never request-derived input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	var parsed any
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA (got %T)", parsed)
	}

	if rsaKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum 2048)", rsaKey.N.BitLen())
	}

	return rsaKey, nil
}

func loadPublicKeyFromPEM(path string) (*rsa.PublicKey, error) {
	// #nosec G703 -- signing-key paths are operator-controlled deployment configuration, never request-derived input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	var key *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		var ok bool
		key, ok = parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA (got %T)", parsed)
		}
	case "RSA PUBLIC KEY":
		parsed, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 public key: %w", err)
		}
		key = parsed
	case "PRIVATE KEY", "RSA PRIVATE KEY":
		privateKey, err := loadPrivateKeyFromPEM(path)
		if err != nil {
			return nil, err
		}
		key = &privateKey.PublicKey
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum 2048)", key.N.BitLen())
	}
	return key, nil
}

func publicKeysEqual(a, b *rsa.PublicKey) bool {
	return a != nil && b != nil && a.E == b.E && a.N.Cmp(b.N) == 0
}

func computeKeyID(pubKey *rsa.PublicKey) (string, error) {
	DER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	hash := sha256.Sum256(DER)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
