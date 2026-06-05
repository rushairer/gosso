package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	dbutil "github.com/rushairer/gosso/internal/db"
)

const (
	defaultBackupCodeCount  = 10
	defaultBackupCodeLength = 8 // 8 bytes = 16 hex chars
)

// TOTPEnrollment TOTP enrollment result
type TOTPEnrollment struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// MFAService multi-factor authentication service
type MFAService struct {
	credentialRepo    accountRepo.CredentialRepository
	passkeySvc        *PasskeyService
	db                *sql.DB
	issuer            string
	totpEncryptionKey []byte
	logger            *zap.Logger
	backupCodeCount   int
	backupCodeLength  int
}

// NewMFAService creates an MFA service instance
func NewMFAService(
	credentialRepo accountRepo.CredentialRepository,
	db *sql.DB,
	issuer string,
	logger *zap.Logger,
	passkeySvc ...*PasskeyService,
) *MFAService {
	if logger == nil {
		logger = zap.NewNop()
	}
	svc := &MFAService{
		credentialRepo:   credentialRepo,
		db:               db,
		issuer:           issuer,
		logger:           logger,
		backupCodeCount:  defaultBackupCodeCount,
		backupCodeLength: defaultBackupCodeLength,
	}
	if len(passkeySvc) > 0 {
		svc.passkeySvc = passkeySvc[0]
	}
	return svc
}

// SetBackupCodeCount overrides the backup code count.
// Must be called during initialization; not safe for concurrent use.
func (s *MFAService) SetBackupCodeCount(n int) {
	if n > 0 {
		s.backupCodeCount = n
	}
}

// SetBackupCodeLength overrides the backup code length.
// Must be called during initialization; not safe for concurrent use.
func (s *MFAService) SetBackupCodeLength(n int) {
	if n > 0 {
		s.backupCodeLength = n
	}
}

// SetTOTPEncryptionKey sets the AES-256 key used to encrypt TOTP secrets at rest.
// Must be called during initialization; not safe for concurrent use.
func (s *MFAService) SetTOTPEncryptionKey(hexKey string) error {
	if hexKey == "" {
		return nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid TOTP encryption key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("TOTP encryption key must be 32 bytes (got %d)", len(key))
	}
	s.totpEncryptionKey = key
	return nil
}

// IsMFAEnabled checks whether the account has TOTP activated or has Passkeys
func (s *MFAService) IsMFAEnabled(ctx context.Context, accountID string) (bool, error) {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		return false, err
	}
	for _, c := range creds {
		if c.Verified && !c.IsDeleted() {
			return true, nil
		}
	}

	if s.passkeySvc != nil {
		has, err := s.passkeySvc.HasPasskeys(ctx, accountID)
		if err != nil {
			s.logger.Warn("Failed to check passkeys for MFA", zap.String("account_id", accountID), zap.Error(err))
		} else if has {
			return true, nil
		}
	}

	return false, nil
}

// GetMFATypes gets the list of available MFA types for the account
func (s *MFAService) GetMFATypes(ctx context.Context, accountID string) []string {
	var types []string

	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		s.logger.Warn("Failed to query TOTP credentials for MFA types", zap.String("account_id", accountID), zap.Error(err))
	} else {
		for _, c := range creds {
			if c.Verified && !c.IsDeleted() {
				types = append(types, "totp")
				break
			}
		}
	}

	if s.passkeySvc != nil {
		has, err := s.passkeySvc.HasPasskeys(ctx, accountID)
		if err != nil {
			s.logger.Warn("Failed to check passkeys for MFA types", zap.String("account_id", accountID), zap.Error(err))
		} else if has {
			types = append(types, "passkey")
		}
	}

	return types
}

// EnrollTOTP starts TOTP enrollment (generates secret, saves to credential, verified=false)
func (s *MFAService) EnrollTOTP(ctx context.Context, accountID string) (*TOTPEnrollment, error) {
	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: accountID,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// Delete existing unverified TOTP credentials
	if err := s.deleteUnverifiedTOTP(ctx, accountID); err != nil {
		s.logger.Warn("Failed to delete unverified TOTP credentials during enrollment", zap.Error(err), zap.String("account_id", accountID))
	}

	// Encrypt secret for storage (if encryption key is configured)
	storedSecret := key.Secret()
	if s.totpEncryptionKey != nil {
		enc, err := encryptSecret(storedSecret, s.totpEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt totp secret: %w", err)
		}
		storedSecret = enc
	}

	// Save as unverified credential
	cred := &accountDomain.Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       accountDomain.CredentialTypeTOTP,
		Identifier: &accountID,
		Value:      storedSecret,
		Verified:   false,
		Metadata:   map[string]any{},
		CreatedAt:  time.Now(),
	}

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.CreateCredentials(ctx, tx, []*accountDomain.Credential{cred})
	})
	if err != nil {
		return nil, fmt.Errorf("save totp credential: %w", err)
	}

	return &TOTPEnrollment{
		Secret:     key.Secret(),
		OTPAuthURL: key.URL(),
	}, nil
}

// VerifyTOTP verifies TOTP code
func (s *MFAService) VerifyTOTP(ctx context.Context, accountID, code string) (bool, error) {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		return false, fmt.Errorf("find totp credential: %w", err)
	}

	for _, c := range creds {
		if !c.IsDeleted() && c.Verified {
			secret := c.Value
			if s.totpEncryptionKey != nil {
				dec, err := decryptSecret(c.Value, s.totpEncryptionKey)
				if err != nil {
					s.logger.Warn("Failed to decrypt TOTP secret, skipping", zap.String("cred_id", c.ID), zap.Error(err))
					continue
				}
				secret = dec
			}
			if totp.Validate(code, secret) {
				return true, nil
			}
		}
	}

	return false, nil
}

// ActivateTOTP activates TOTP (marks as verified)
func (s *MFAService) ActivateTOTP(ctx context.Context, accountID, code string) error {
	// Verify code first
	valid, err := s.VerifyTOTP(ctx, accountID, code)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid TOTP code")
	}

	// Atomically verify the first unverified TOTP credential in a transaction
	// Using FOR UPDATE SKIP LOCKED prevents concurrent activation race conditions
	var activated bool
	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		var txErr error
		activated, txErr = s.credentialRepo.VerifyFirstUnverifiedTOTP(ctx, tx, accountID)
		return txErr
	})
	if err != nil {
		return fmt.Errorf("activate totp credential: %w", err)
	}
	if !activated {
		return errors.New("no pending TOTP enrollment found")
	}

	return nil
}

// DisableTOTP disables TOTP
func (s *MFAService) DisableTOTP(ctx context.Context, accountID string) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		return fmt.Errorf("find totp credential: %w", err)
	}

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		for _, c := range creds {
			if !c.IsDeleted() {
				if err := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); err != nil {
					return fmt.Errorf("delete TOTP credential %s: %w", c.ID, err)
				}
			}
		}

		// Also delete all backup codes
		backupCreds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeBackupCode)
		if err != nil {
			return fmt.Errorf("find backup code credentials: %w", err)
		}
		for _, c := range backupCreds {
			if !c.IsDeleted() {
				if err := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); err != nil {
					return fmt.Errorf("delete backup code credential %s: %w", c.ID, err)
				}
			}
		}
		return nil
	})
	return err
}

// GenerateBackupCodes generates backup codes
func (s *MFAService) GenerateBackupCodes(ctx context.Context, accountID string) ([]string, error) {
	var codes []string
	var creds []*accountDomain.Credential

	for i := 0; i < s.backupCodeCount; i++ {
		code, err := generateRandomCode(s.backupCodeLength)
		if err != nil {
			return nil, fmt.Errorf("generate backup code: %w", err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash backup code: %w", err)
		}

		codes = append(codes, code)
		creds = append(creds, &accountDomain.Credential{
			ID:         uuid.New().String(),
			AccountID:  accountID,
			Type:       accountDomain.CredentialTypeBackupCode,
			Identifier: &accountID,
			Value:      string(hash),
			Verified:   true,
			Metadata:   map[string]any{},
			CreatedAt:  time.Now(),
		})
	}

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Delete old backup codes in the same transaction
		oldCreds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeBackupCode)
		if err != nil {
			return fmt.Errorf("find old backup codes: %w", err)
		}
		for _, c := range oldCreds {
			if !c.IsDeleted() {
				if err := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); err != nil {
					return fmt.Errorf("delete old backup code: %w", err)
				}
			}
		}
		// Create new backup codes
		return s.credentialRepo.CreateCredentials(ctx, tx, creds)
	})
	if err != nil {
		return nil, fmt.Errorf("generate backup codes: %w", err)
	}

	return codes, nil
}

// VerifyBackupCode verifies backup code (deletes it upon successful verification).
// The entire find-bcrypt-delete sequence runs in a single transaction with FOR UPDATE locking
// to prevent a backup code from being used by concurrent requests.
func (s *MFAService) VerifyBackupCode(ctx context.Context, accountID, code string) (bool, error) {
	var verified bool
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		creds, err := s.credentialRepo.FindByAccountAndTypeForUpdate(ctx, tx, accountID, accountDomain.CredentialTypeBackupCode)
		if err != nil {
			return fmt.Errorf("find backup codes: %w", err)
		}

		for _, c := range creds {
			if c.IsDeleted() || !c.Verified {
				continue
			}
			if bcrypt.CompareHashAndPassword([]byte(c.Value), []byte(code)) == nil {
				if err := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); err != nil {
					return fmt.Errorf("delete backup code: %w", err)
				}
				verified = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return verified, nil
}

func (s *MFAService) deleteUnverifiedTOTP(ctx context.Context, accountID string) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		s.logger.Warn("Failed to find TOTP credentials for cleanup", zap.Error(err), zap.String("account_id", accountID))
		return err
	}
	return dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		for _, c := range creds {
			if !c.Verified && !c.IsDeleted() {
				if err := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); err != nil {
					s.logger.Error("Failed to soft-delete unverified TOTP", zap.String("cred_id", c.ID), zap.Error(err))
					return fmt.Errorf("soft delete credential: %w", err)
				}
			}
		}
		return nil
	})
}

func generateRandomCode(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random code: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// encryptSecret encrypts a plaintext secret using AES-256-GCM.
// Returns hex-encoded nonce + ciphertext.
func encryptSecret(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptSecret decrypts a hex-encoded nonce+ciphertext using AES-256-GCM.
func decryptSecret(encoded string, key []byte) (string, error) {
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
