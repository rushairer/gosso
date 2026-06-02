package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
)

const (
	VerifyCodeKeyPrefix  = "verify:code:"
	VerifyCooldownPrefix = "verify:cooldown:"
	VerifyCodeAttempts   = 5
	VerifyCodeTTL        = 10 * time.Minute
	VerifyCooldownTTL    = 60 * time.Second
	VerifyCodeLength     = 6
)

// EmailSender 邮件发送接口
type EmailSender interface {
	SendVerificationCode(ctx context.Context, to, code string) error
}

// SMSSender 短信发送接口
type SMSSender interface {
	SendVerificationCode(ctx context.Context, phone, code string) error
}

// VerificationService 验证码管理服务
type VerificationService struct {
	redis    *cache.RedisClient
	emailSvc EmailSender
	smsSvc   SMSSender
	logger   *zap.Logger
}

// NewVerificationService 创建验证码服务实例
func NewVerificationService(
	redis *cache.RedisClient,
	emailSvc EmailSender,
	smsSvc SMSSender,
	logger *zap.Logger,
) *VerificationService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &VerificationService{
		redis:    redis,
		emailSvc: emailSvc,
		smsSvc:   smsSvc,
		logger:   logger,
	}
}

type verifyCodeData struct {
	Code      string `json:"code"`
	Attempts  int    `json:"attempts"`
	AccountID string `json:"account_id"`
}

// SendCode 发送验证码
func (s *VerificationService) SendCode(ctx context.Context, credType, identifier, accountID string) error {
	// 检查冷却
	cooldownKey := s.buildCooldownKey(credType, identifier)
	exists, err := s.redis.Exists(ctx, cooldownKey)
	if err != nil {
		s.logger.Warn("Failed to check cooldown", zap.Error(err))
	}
	if exists {
		return errors.New("please wait before requesting another code")
	}

	// 生成 6 位随机数字码
	code, err := generateNumericCode(VerifyCodeLength)
	if err != nil {
		return fmt.Errorf("generate code: %w", err)
	}

	// 存储到 Redis
	data := verifyCodeData{
		Code:      code,
		Attempts:  0,
		AccountID: accountID,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal code data: %w", err)
	}

	codeKey := s.buildCodeKey(credType, identifier)
	if err := s.redis.Set(ctx, codeKey, jsonData, VerifyCodeTTL); err != nil {
		return fmt.Errorf("store code: %w", err)
	}

	// 设置冷却
	if err := s.redis.Set(ctx, cooldownKey, []byte("1"), VerifyCooldownTTL); err != nil {
		s.logger.Warn("Failed to set cooldown", zap.Error(err))
	}

	// 发送
	switch credType {
	case "email":
		if err := s.emailSvc.SendVerificationCode(ctx, identifier, code); err != nil {
			return fmt.Errorf("send email: %w", err)
		}
	case "phone":
		if err := s.smsSvc.SendVerificationCode(ctx, identifier, code); err != nil {
			return fmt.Errorf("send SMS: %w", err)
		}
	default:
		return fmt.Errorf("unsupported credential type: %s", credType)
	}

	s.logger.Info("Verification code sent",
		zap.String("type", credType),
		zap.String("identifier", identifier))
	return nil
}

// VerifyCode 验证码校验，成功返回 accountID
func (s *VerificationService) VerifyCode(ctx context.Context, credType, identifier, code string) (string, error) {
	codeKey := s.buildCodeKey(credType, identifier)

	raw, err := s.redis.Get(ctx, codeKey)
	if err == cache.ErrKeyNotFound {
		return "", errors.New("verification code expired or not found")
	}
	if err != nil {
		return "", fmt.Errorf("get code: %w", err)
	}

	var data verifyCodeData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return "", fmt.Errorf("unmarshal code data: %w", err)
	}

	// 检查尝试次数
	if data.Attempts >= VerifyCodeAttempts {
		_ = s.redis.Del(ctx, codeKey)
		return "", errors.New("verification code exhausted, please request a new one")
	}

	// 比对码
	if data.Code != code {
		data.Attempts++
		updatedData, _ := json.Marshal(data)
		_ = s.redis.Set(ctx, codeKey, updatedData, VerifyCodeTTL)
		return "", errors.New("invalid verification code")
	}

	// 成功 → 删除 Redis key
	_ = s.redis.Del(ctx, codeKey)

	return data.AccountID, nil
}

func (s *VerificationService) buildCodeKey(credType, identifier string) string {
	return fmt.Sprintf("%s%s:%s", VerifyCodeKeyPrefix, credType, identifier)
}

func (s *VerificationService) buildCooldownKey(credType, identifier string) string {
	return fmt.Sprintf("%s%s:%s", VerifyCooldownPrefix, credType, identifier)
}

func generateNumericCode(length int) (string, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", length, n), nil
}
