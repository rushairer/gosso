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
)

// rsaKeyBits is the key size for new RSA key generation.
// NOTE: Existing keys are not affected; rotate keys to upgrade.
const rsaKeyBits = 3072

// KeyService manages RSA key pairs for RS256 JWT signing.
type KeyService struct {
	privateKey *rsa.PrivateKey
	keyID      string
	logger     *zap.Logger
}

// NewKeyService creates a KeyService. Loading/generation strategy:
//  1. privateKeyPath non-empty and file exists → load from PEM
//  2. privateKeyPath non-empty and file missing → generate and write PEM
//  3. privateKeyPath empty → generate in-memory (dev mode, keys lost on restart)
func NewKeyService(privateKeyPath string, keyID string, logger *zap.Logger) (*KeyService, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	var privateKey *rsa.PrivateKey
	var err error

	if privateKeyPath != "" {
		if _, statErr := os.Stat(privateKeyPath); statErr == nil {
			privateKey, err = loadPrivateKeyFromPEM(privateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("load private key: %w", err)
			}
			logger.Info("RSA private key loaded from file", zap.String("path", privateKeyPath))
		} else {
			privateKey, err = generateAndSaveKey(privateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("generate and save key: %w", err)
			}
			logger.Warn("RSA private key file not found — generating NEW key. All previously issued tokens will be INVALID.",
				zap.String("path", privateKeyPath))
		}
	} else {
		privateKey, err = generateKey()
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

func generateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeyBits)
}

func generateAndSaveKey(path string) (*rsa.PrivateKey, error) {
	key, err := generateKey()
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

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}); err != nil {
		return fmt.Errorf("encode PEM: %w", err)
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

	return rsaKey, nil
}

func computeKeyID(pubKey *rsa.PublicKey) (string, error) {
	DER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	hash := sha256.Sum256(DER)
	return base64.RawURLEncoding.EncodeToString(hash[:8]), nil
}

// BigEndianBytes converts an int to its big-endian byte representation.
func BigEndianBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var bytes []byte
	for v := e; v > 0; v >>= 8 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
	}
	return bytes
}
