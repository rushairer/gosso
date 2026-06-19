package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/utility"
)

const defaultRSAKeyBits = 3072

// SetRSAKeyBits is a no-op kept for backward compatibility.
//
// Deprecated: pass keyBits directly to NewKeyService instead.
// Will be removed in v2.0.0.
func SetRSAKeyBits(_ int) {}

// KeyService manages RSA key pairs for RS256 JWT signing.
type KeyService struct {
	privateKey *rsa.PrivateKey
	keyID      string
	logger     *zap.Logger
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

	return &KeyService{
		privateKey: privateKey,
		keyID:      kid,
		logger:     logger,
	}, nil
}

func (s *KeyService) PrivateKey() *rsa.PrivateKey {
	return s.privateKey
}

func (s *KeyService) PublicKey() *rsa.PublicKey {
	return &s.privateKey.PublicKey
}

func (s *KeyService) KeyID() string {
	return s.keyID
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA (got %T)", key)
	}

	if rsaKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum 2048)", rsaKey.N.BitLen())
	}

	return rsaKey, nil
}

func computeKeyID(pubKey *rsa.PublicKey) (string, error) {
	DER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	hash := sha256.Sum256(DER)
	// Use full SHA-256 hash per RFC 7638 (JWK Thumbprint).
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
