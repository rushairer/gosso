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
	dbutil "github.com/rushairer/gosso/internal/db"
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
			err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
				return s.credentialRepo.UpdateCredential(ctx, tx, c)
			})
			if err != nil {
				return fmt.Errorf("update totp credential: %w", err)
			}
			return nil
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

	err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
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
		return nil
	})
	return err
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

	err := dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
		return s.credentialRepo.CreateCredentials(ctx, tx, creds)
	})
	if err != nil {
		return nil, fmt.Errorf("save backup codes: %w", err)
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
			err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
				return s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now())
			})
			if err != nil {
				s.logger.Error("Failed to soft-delete backup code", zap.String("cred_id", c.ID), zap.Error(err))
				return false, fmt.Errorf("delete backup code: %w", err)
			}
			return true, nil
		}
	}

	return false, nil
}

func (s *MFAService) deleteUnverifiedTOTP(ctx context.Context, accountID string) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeTOTP)
	if err != nil {
		s.logger.Warn("Failed to find TOTP credentials for cleanup", zap.Error(err), zap.String("account_id", accountID))
		return err
	}
	for _, c := range creds {
		if !c.Verified && !c.IsDeleted() {
			err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
				return s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now())
			})
			if err != nil {
				s.logger.Error("Failed to soft-delete unverified TOTP", zap.String("cred_id", c.ID), zap.Error(err))
				return fmt.Errorf("soft delete credential: %w", err)
			}
		}
	}
	return nil
}

func (s *MFAService) deleteBackupCodes(ctx context.Context, accountID string) error {
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialTypeBackupCode)
	if err != nil {
		s.logger.Warn("Failed to find backup code credentials for cleanup", zap.Error(err), zap.String("account_id", accountID))
		return err
	}
	for _, c := range creds {
		if !c.IsDeleted() {
			err = dbutil.RunInTransaction(ctx, s.db, func(tx *sql.Tx) error {
				return s.credentialRepo.SoftDeleteCredential(ctx, tx, c.ID, time.Now())
			})
			if err != nil {
				s.logger.Error("Failed to soft-delete backup code", zap.String("cred_id", c.ID), zap.Error(err))
				return fmt.Errorf("soft delete credential: %w", err)
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
