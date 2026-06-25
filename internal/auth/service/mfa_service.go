package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	dbutil "github.com/rushairer/gosso/internal/db"
	"github.com/rushairer/gosso/internal/utility"
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

// MFAServiceConfig holds optional configuration for MFAService.
// Zero-valued fields use package defaults.
type MFAServiceConfig struct {
	TOTPEncryptionKey string // hex-encoded AES-256 key; empty = no encryption
	BackupCodeCount   int    // default: defaultBackupCodeCount
	BackupCodeLength  int    // default: defaultBackupCodeLength
}

// NewMFAService creates an MFA service instance.
// passkeySvc is optional and may be nil.
func NewMFAService(
	credentialRepo accountRepo.CredentialRepository,
	db *sql.DB,
	issuer string,
	logger *zap.Logger,
	passkeySvc *PasskeyService,
) (*MFAService, error) {
	return NewMFAServiceWithConfig(credentialRepo, db, issuer, logger, MFAServiceConfig{}, passkeySvc)
}

// NewMFAServiceWithConfig creates an MFA service instance with the given config.
// Zero-valued config fields use package defaults.
func NewMFAServiceWithConfig(
	credentialRepo accountRepo.CredentialRepository,
	db *sql.DB,
	issuer string,
	logger *zap.Logger,
	cfg MFAServiceConfig,
	passkeySvc *PasskeyService,
) (*MFAService, error) {
	logger = utility.EnsureLogger(logger)
	svc := &MFAService{
		credentialRepo:   credentialRepo,
		db:               db,
		issuer:           issuer,
		logger:           logger,
		passkeySvc:       passkeySvc,
		backupCodeCount:  defaultBackupCodeCount,
		backupCodeLength: defaultBackupCodeLength,
	}
	if cfg.TOTPEncryptionKey != "" {
		key, err := hex.DecodeString(cfg.TOTPEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid TOTP encryption key: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("%w: TOTP encryption key must be 32 bytes (got %d)", ErrInvalidConfig, len(key))
		}
		svc.totpEncryptionKey = key
	}
	if cfg.BackupCodeCount > 0 && cfg.BackupCodeCount <= 20 {
		svc.backupCodeCount = cfg.BackupCodeCount
	}
	if cfg.BackupCodeLength > 0 && cfg.BackupCodeLength <= 12 {
		svc.backupCodeLength = cfg.BackupCodeLength
	}
	return svc, nil
}

// RequireTOTPEncryption returns an error if no TOTP encryption key is configured.
// Call this during startup for production deployments to prevent TOTP secrets
// from being stored in plaintext in the database.
func (s *MFAService) RequireTOTPEncryption() error {
	if s.totpEncryptionKey == nil {
		return fmt.Errorf("TOTP encryption key is required for production deployments: " +
			"set auth.totp_encryption_key (env GOUNO_AUTH_TOTP_ENCRYPTION_KEY) to a 64-char hex string (32 bytes)")
	}
	return nil
}

// MFAStatus holds the combined MFA status for an account.
type MFAStatus struct {
	Enabled bool     `json:"enabled"`
	Types   []string `json:"types"`
}

// GetMFAStatus returns the MFA enabled flag and the list of available MFA types
// in a single pass, avoiding redundant DB queries when both values are needed.
func (s *MFAService) GetMFAStatus(ctx context.Context, accountID string) (*MFAStatus, error) {
	status := &MFAStatus{}

	g, gctx := errgroup.WithContext(ctx)

	var creds []*accountDomain.Credential
	var hasPasskeys bool

	// Query TOTP credentials and passkey existence concurrently.
	g.Go(func() error {
		var err error
		creds, err = s.credentialRepo.FindByAccountAndType(gctx, accountID, accountDomain.CredentialTypeTOTP)
		if err != nil {
			return fmt.Errorf("query TOTP credentials: %w", err)
		}
		return nil
	})

	if s.passkeySvc != nil {
		g.Go(func() error {
			var err error
			hasPasskeys, err = s.passkeySvc.HasPasskeys(gctx, accountID)
			if err != nil {
				return fmt.Errorf("check passkeys: %w", err)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	for _, c := range creds {
		if c.Verified && !c.IsDeleted() {
			status.Enabled = true
			status.Types = append(status.Types, "totp")
			break
		}
	}

	if hasPasskeys {
		status.Types = append(status.Types, "passkey")
	}

	return status, nil
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

	// Encrypt secret for storage (if encryption key is configured)
	storedSecret := key.Secret()
	if s.totpEncryptionKey != nil {
		enc, encErr := encryptSecret(storedSecret, s.totpEncryptionKey)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt totp secret: %w", encErr)
		}
		storedSecret = enc
	} else {
		s.logger.Error("TOTP encryption key not configured; refusing to store secret in plaintext. " +
			"Set auth.totp_encryption_key (env GOUNO_AUTH_TOTP_ENCRYPTION_KEY).")
		return nil, fmt.Errorf("totp encryption key not configured")
	}

	// Delete existing unverified TOTP credentials and save the new one atomically.
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
		// Delete unverified TOTP credentials in the same transaction to prevent race conditions
		existingCreds, findErr := s.credentialRepo.FindByAccountAndTypeTx(ctx, tx, accountID, accountDomain.CredentialTypeTOTP)
		if findErr != nil {
			return fmt.Errorf("find existing totp credentials: %w", findErr)
		}
		for _, c := range existingCreds {
			if !c.Verified && !c.IsDeleted() {
				if delErr := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); delErr != nil {
					return fmt.Errorf("soft delete old totp credential %s: %w", c.ID, delErr)
				}
			}
		}
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

	var decryptFailures int
	var totalVerified int
	for _, c := range creds {
		if !c.IsDeleted() && c.Verified {
			totalVerified++
			secret := c.Value
			if s.totpEncryptionKey != nil {
				dec, err := decryptSecret(c.Value, s.totpEncryptionKey)
				if err != nil {
					s.logger.Error("Failed to decrypt TOTP secret", zap.String("cred_id", c.ID), zap.Error(err))
					decryptFailures++
					continue
				}
				secret = dec
			}
			if totp.Validate(code, secret) {
				return true, nil
			}
		}
	}

	// If all verified credentials failed to decrypt, this is a configuration problem
	if totalVerified > 0 && decryptFailures == totalVerified {
		return false, fmt.Errorf("all TOTP credentials failed to decrypt: check totp_encryption_key configuration")
	}

	return false, nil
}

// verifyTOTPIncludeUnverified verifies TOTP code against ALL non-deleted credentials,
// including those with Verified=false. Used by ActivateTOTP during first-time enrollment
// when the only credential is the newly enrolled (unverified) one.
func (s *MFAService) verifyTOTPIncludeUnverified(ctx context.Context, accountID, code string) (bool, error) {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		return false, fmt.Errorf("find totp credential: %w", err)
	}

	for _, c := range creds {
		if c.IsDeleted() {
			continue
		}
		secret := c.Value
		if s.totpEncryptionKey != nil {
			dec, err := decryptSecret(c.Value, s.totpEncryptionKey)
			if err != nil {
				s.logger.Error("Failed to decrypt TOTP secret", zap.String("cred_id", c.ID), zap.Error(err))
				continue
			}
			secret = dec
		}
		if totp.Validate(code, secret) {
			return true, nil
		}
	}

	return false, nil
}

// ActivateTOTP activates TOTP (marks as verified)
func (s *MFAService) ActivateTOTP(ctx context.Context, accountID, code string) error {
	// Verify code against ALL non-deleted TOTP credentials, including unverified ones.
	// During first-time enrollment, the only credential is the newly enrolled one
	// (Verified=false). The standard VerifyTOTP skips unverified credentials, so we
	// use a dedicated activation verification that checks all non-deleted credentials.
	valid, err := s.verifyTOTPIncludeUnverified(ctx, accountID, code)
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidMFACode
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
		return ErrNoPendingTOTPEnrollment
	}

	return nil
}

// softDeleteCredentialsByType soft-deletes all credentials of the given type for the account
// in a single UPDATE statement. Must be called within a transaction.
func (s *MFAService) softDeleteCredentialsByType(ctx context.Context, tx *sql.Tx, accountID string, credType accountDomain.CredentialType) error {
	if err := s.credentialRepo.SoftDeleteCredentialsByType(ctx, tx, accountID, credType, time.Now()); err != nil {
		return fmt.Errorf("delete %s credentials: %w", credType, err)
	}
	return nil
}

// DisableTOTP disables TOTP
func (s *MFAService) DisableTOTP(ctx context.Context, accountID string) error {
	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if err := s.softDeleteCredentialsByType(ctx, tx, accountID, accountDomain.CredentialTypeTOTP); err != nil {
			return err
		}
		// Also delete all backup codes when TOTP is disabled
		return s.softDeleteCredentialsByType(ctx, tx, accountID, accountDomain.CredentialTypeBackupCode)
	})
	if err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	return nil
}

// GenerateBackupCodes generates backup codes.
// Hashing is parallelised with a bounded worker pool so that the serial
// bcrypt calls don't block the request handler for ~1 s.
func (s *MFAService) GenerateBackupCodes(ctx context.Context, accountID string) ([]string, error) {
	codes := make([]string, s.backupCodeCount)
	hashes := make([][]byte, s.backupCodeCount)

	// First generate all plaintext codes.
	for i := 0; i < s.backupCodeCount; i++ {
		code, err := generateRandomCode(s.backupCodeLength)
		if err != nil {
			return nil, fmt.Errorf("generate backup code: %w", err)
		}
		codes[i] = code
	}

	// Hash codes in parallel (bcrypt is CPU-bound; GOMAXPROCS workers).
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.backupCodeCount)
	for i := 0; i < s.backupCodeCount; i++ {
		g.Go(func() error {
			hash, err := bcrypt.GenerateFromPassword([]byte(codes[i]), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("hash backup code: %w", err)
			}
			// Abort early if the parent context was canceled (e.g., client disconnect).
			if gctx.Err() != nil {
				return gctx.Err()
			}
			hashes[i] = hash
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Build credential records from the pre-computed hashes.
	creds := make([]*accountDomain.Credential, s.backupCodeCount)
	for i := 0; i < s.backupCodeCount; i++ {
		creds[i] = &accountDomain.Credential{
			ID:         uuid.New().String(),
			AccountID:  accountID,
			Type:       accountDomain.CredentialTypeBackupCode,
			Identifier: &accountID,
			Value:      string(hashes[i]),
			Verified:   true,
			Metadata:   map[string]any{},
			CreatedAt:  time.Now(),
		}
	}

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		// Delete old backup codes in the same transaction
		if err := s.softDeleteCredentialsByType(ctx, tx, accountID, accountDomain.CredentialTypeBackupCode); err != nil {
			return err
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
		return "", fmt.Errorf("%w: %s", ErrCiphertextTooShort, "data shorter than nonce size")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
