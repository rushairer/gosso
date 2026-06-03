package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
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

// verifyAndIncrementScript atomically verifies a code and manages the attempt counter.
// Returns JSON array: ["ok", accountID] | ["mismatch", ""] | ["exhausted", ""] | ["not_found", ""]
// ARGV[1]=code, ARGV[2]=max_attempts, ARGV[3]=default_ttl_seconds
var verifyAndIncrementScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return cjson.encode({"not_found", ""})
end
local cjson = require('cjson')
local obj = cjson.decode(data)
local max_attempts = tonumber(ARGV[2])
if obj.attempts >= max_attempts then
    redis.call('DEL', KEYS[1])
    return cjson.encode({"exhausted", ""})
end
if obj.code == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return cjson.encode({"ok", obj.account_id})
end
obj.attempts = obj.attempts + 1
local default_ttl = tonumber(ARGV[3])
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
    redis.call('SETEX', KEYS[1], ttl, cjson.encode(obj))
else
    redis.call('SETEX', KEYS[1], default_ttl, cjson.encode(obj))
end
return cjson.encode({"mismatch", ""})
`)

// EmailSender email sending interface
type EmailSender interface {
	SendVerificationCode(ctx context.Context, to, code string) error
}

// SMSSender SMS sending interface
type SMSSender interface {
	SendVerificationCode(ctx context.Context, phone, code string) error
}

// VerificationService verification code management service
type VerificationService struct {
	redis    *cache.RedisClient
	emailSvc EmailSender
	smsSvc   SMSSender
	logger   *zap.Logger
}

// NewVerificationService creates a new verification service instance
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

// SendCode sends verification code
func (s *VerificationService) SendCode(ctx context.Context, credType, identifier, accountID string) error {
	// Check cooldown (fail-open: if Redis is down, we still allow the request)
	cooldownKey := s.buildCooldownKey(credType, identifier)
	exists, err := s.redis.Exists(ctx, cooldownKey)
	if err != nil {
		s.logger.Warn("Failed to check cooldown, proceeding anyway", zap.Error(err))
	}
	if exists {
		return errors.New("please wait before requesting another code")
	}

	// Generate 6-digit random numeric code
	code, err := generateNumericCode(VerifyCodeLength)
	if err != nil {
		return fmt.Errorf("generate code: %w", err)
	}

	// Store in Redis
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

	// Set cooldown (fail-open: if Redis is down, we lose cooldown but can still verify)
	if err := s.redis.Set(ctx, cooldownKey, []byte("1"), VerifyCooldownTTL); err != nil {
		s.logger.Warn("Failed to set cooldown", zap.Error(err))
	}

	// Send
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
		zap.String("identifier", maskIdentifier(credType, identifier)))
	return nil
}

// VerifyCode verifies verification code, returns accountID upon success
func (s *VerificationService) VerifyCode(ctx context.Context, credType, identifier, code string) (string, error) {
	codeKey := s.buildCodeKey(credType, identifier)

	// Atomically verify code and increment attempts
	resultJSON, err := verifyAndIncrementScript.Run(ctx, s.redis.GetClient(), []string{codeKey},
		code, VerifyCodeAttempts, int(VerifyCodeTTL.Seconds())).Result()
	if err != nil {
		return "", fmt.Errorf("verify code: %w", err)
	}

	resultStr, ok := resultJSON.(string)
	if !ok {
		return "", fmt.Errorf("unexpected verify result type")
	}

	var result []string
	if err := json.Unmarshal([]byte(resultStr), &result); err != nil || len(result) < 2 {
		return "", fmt.Errorf("unmarshal verify result: %w", err)
	}

	switch result[0] {
	case "ok":
		return result[1], nil
	case "not_found":
		return "", errors.New("verification code expired or not found")
	case "exhausted":
		return "", errors.New("verification code exhausted, please request a new one")
	case "mismatch":
		return "", errors.New("invalid verification code")
	default:
		return "", fmt.Errorf("unknown verify status: %s", result[0])
	}
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

// maskIdentifier masks PII for logging (e.g., "user@example.com" -> "u***@e***.com")
func maskIdentifier(credType, identifier string) string {
	switch credType {
	case "email":
		atIdx := -1
		for i, c := range identifier {
			if c == '@' {
				atIdx = i
				break
			}
		}
		if atIdx > 0 && atIdx < len(identifier)-1 {
			local := identifier[:atIdx]
			domain := identifier[atIdx+1:]
			maskedLocal := string(local[0]) + "***"
			dotIdx := -1
			for i, c := range domain {
				if c == '.' {
					dotIdx = i
					break
				}
			}
			var maskedDomain string
			if dotIdx > 0 {
				maskedDomain = string(domain[0]) + "***" + domain[dotIdx:]
			} else {
				maskedDomain = string(domain[0]) + "***"
			}
			return maskedLocal + "@" + maskedDomain
		}
		if len(identifier) > 1 {
			return string(identifier[0]) + "***"
		}
		return "***"
	case "phone":
		if len(identifier) > 4 {
			return identifier[:3] + "***" + identifier[len(identifier)-2:]
		}
		return "***"
	default:
		return "***"
	}
}
