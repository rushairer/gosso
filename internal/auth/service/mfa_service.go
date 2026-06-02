package service

import (
	"context"
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
)

const (
	backupCodeCount  = 10
	backupCodeLength = 8 // 8 bytes = 16 hex chars
)

// TOTPEnrollment TOTP enrollment result
type TOTPEnrollment struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// MFAService multi-factor authentication service
type MFAService struct {
	credentialRepo accountRepo.CredentialRepository
	passkeySvc     *PasskeyService
	db             *sql.DB
	issuer         string
	logger         *zap.Logger
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
		credentialRepo: credentialRepo,
		db:             db,
		issuer:         issuer,
		logger:         logger,
	}
	if len(passkeySvc) > 0 {
		svc.passkeySvc = passkeySvc[0]
	}
	return svc
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
		if err == nil && has {
			return true, nil
		}
	}

	return false, nil
}

// GetMFATypes gets the list of available MFA types for the account
func (s *MFAService) GetMFATypes(ctx context.Context, accountID string) []string {
	var types []string

	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err == nil {
		for _, c := range creds {
			if c.Verified && !c.IsDeleted() {
				types = append(types, "totp")
				break
			}
		}
	}

	if s.passkeySvc != nil {
		has, err := s.passkeySvc.HasPasskeys(ctx, accountID)
		if err == nil && has {
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
	_ = s.deleteUnverifiedTOTP(ctx, accountID)

	// Save as unverified credential
	cred := &accountDomain.Credential{
		ID:         uuid.New().String(),
		AccountID:  accountID,
		Type:       accountDomain.CredentialTypeTOTP,
		Identifier: &accountID,
		Value:      key.Secret(),
		Verified:   false,
		Metadata:   map[string]any{},
		CreatedAt:  time.Now(),
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.credentialRepo.CreateCredentials(ctx, tx, []*accountDomain.Credential{cred}); err != nil {
		return nil, fmt.Errorf("save totp credential: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
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
		if !c.IsDeleted() && totp.Validate(code, c.Value) {
			return true, nil
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

	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		return fmt.Errorf("find totp credential: %w", err)
	}

	for _, c := range creds {
		if !c.Verified && !c.IsDeleted() {
			c.Verify()
			tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if err != nil {
				return fmt.Errorf("begin transaction: %w", err)
			}
			defer func() { _ = tx.Rollback() }()

			if err := s.credentialRepo.UpdateCredential(ctx, tx, c); err != nil {
				return fmt.Errorf("update totp credential: %w", err)
			}
			return tx.Commit()
		}
	}

	return errors.New("no pending TOTP enrollment found")
}

// DisableTOTP disables TOTP
func (s *MFAService) DisableTOTP(ctx context.Context, accountID string) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		return fmt.Errorf("find totp credential: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, c := range creds {
		if !c.IsDeleted() {
			if err := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); err != nil {
				s.logger.Warn("Failed to delete TOTP credential", zap.String("cred_id", c.ID), zap.Error(err))
			}
		}
	}

	// Also delete all backup codes
	backupCreds, _ := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeBackupCode)
	for _, c := range backupCreds {
		if !c.IsDeleted() {
			if err := s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now()); err != nil {
				s.logger.Warn("Failed to delete backup code credential", zap.String("cred_id", c.ID), zap.Error(err))
			}
		}
	}

	return tx.Commit()
}

// GenerateBackupCodes generates backup codes
func (s *MFAService) GenerateBackupCodes(ctx context.Context, accountID string) ([]string, error) {
	// Delete old backup codes
	_ = s.deleteBackupCodes(ctx, accountID)

	var codes []string
	var creds []*accountDomain.Credential

	for i := 0; i < backupCodeCount; i++ {
		code := generateRandomCode(backupCodeLength)
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

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.credentialRepo.CreateCredentials(ctx, tx, creds); err != nil {
		return nil, fmt.Errorf("save backup codes: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return codes, nil
}

// VerifyBackupCode verifies backup code (deletes it upon successful verification)
func (s *MFAService) VerifyBackupCode(ctx context.Context, accountID, code string) (bool, error) {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeBackupCode)
	if err != nil {
		return false, fmt.Errorf("find backup codes: %w", err)
	}

	for _, c := range creds {
		if c.IsDeleted() || !c.Verified {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(c.Value), []byte(code)) == nil {
			// Success, delete the code
			tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if err != nil {
				s.logger.Warn("Failed to begin tx for backup code deletion", zap.Error(err))
				return true, nil // Verification passed but deletion failed, still return true
			}
			_ = s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now())
			_ = tx.Commit()
			return true, nil
		}
	}

	return false, nil
}

func (s *MFAService) deleteUnverifiedTOTP(ctx context.Context, accountID string) error {
	creds, _ := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	for _, c := range creds {
		if !c.Verified && !c.IsDeleted() {
			tx, _ := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if tx != nil {
				_ = s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now())
				_ = tx.Commit()
			}
		}
	}
	return nil
}

func (s *MFAService) deleteBackupCodes(ctx context.Context, accountID string) error {
	creds, _ := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeBackupCode)
	for _, c := range creds {
		if !c.IsDeleted() {
			tx, _ := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if tx != nil {
				_ = s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now())
				_ = tx.Commit()
			}
		}
	}
	return nil
}

func generateRandomCode(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
