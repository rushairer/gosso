package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"go.uber.org/zap"
)

const (
	backupCodeCount  = 10
	backupCodeLength = 8 // 8 bytes = 16 hex chars
)

// TOTPEnrollment TOTP 注册结果
type TOTPEnrollment struct {
	Secret    string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// MFAService 多因素认证服务
type MFAService struct {
	credentialRepo accountRepo.CredentialRepository
	passkeySvc     *PasskeyService
	db             *sql.DB
	issuer         string
	logger         *zap.Logger
}

// NewMFAService 创建 MFA 服务实例
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

// IsMFAEnabled 检查账号是否已激活 TOTP 或拥有 Passkey
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

// GetMFATypes 获取账号可用的 MFA 类型列表
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

// EnrollTOTP 开始 TOTP 注册（生成 secret，存入 credential，verified=false）
func (s *MFAService) EnrollTOTP(ctx context.Context, accountID string) (*TOTPEnrollment, error) {
	// 生成 TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: accountID,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// 删除已有的未验证 TOTP 凭证
	_ = s.deleteUnverifiedTOTP(ctx, accountID)

	// 存储为未验证的 credential
	cred := &accountDomain.Credential{
		ID:        newUUID(),
		AccountID: accountID,
		Type:      accountDomain.CredentialTypeTOTP,
		Identifier: &accountID,
		Value:     key.Secret(),
		Verified:  false,
		Metadata:  map[string]any{},
		CreatedAt: time.Now(),
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

// VerifyTOTP 验证 TOTP 码
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

// ActivateTOTP 激活 TOTP（标记为已验证）
func (s *MFAService) ActivateTOTP(ctx context.Context, accountID, code string) error {
	// 先验证 code
	valid, err := s.VerifyTOTP(ctx, accountID, code)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid TOTP code")
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

	return fmt.Errorf("no pending TOTP enrollment found")
}

// DisableTOTP 禁用 TOTP
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

	// 同时删除所有 backup codes
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

// GenerateBackupCodes 生成备用码
func (s *MFAService) GenerateBackupCodes(ctx context.Context, accountID string) ([]string, error) {
	// 删除旧的 backup codes
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
			ID:         newUUID(),
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

// VerifyBackupCode 验证备用码（成功后删除该码）
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
			// 成功，删除该码
			tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if err != nil {
				return true, nil // 验证通过但删除失败，仍返回 true
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

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
