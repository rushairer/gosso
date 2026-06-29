package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountRepo "github.com/rushairer/gosso/internal/account/repository"
	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	verifyCodeKeyPrefix  = "verify:code:"
	verifyCooldownPrefix = "verify:cooldown:"
	verifyCodeAttempts   = 5
	verifyCodeTTL        = 10 * time.Minute
	verifyCooldownTTL    = 60 * time.Second
	verifyCodeLength     = 6
)

// Sentinel errors for verification service operations.
var (
	ErrCooldownActive            = errors.New("verification cooldown active")
	ErrUnsupportedType           = errors.New("unsupported verification type")
	ErrVerificationCodeExpired   = errors.New("verification code expired or not found")
	ErrVerificationCodeExhausted = errors.New("verification code exhausted, please request a new one")
	ErrVerificationCodeInvalid   = errors.New("invalid verification code")
)

// verifyAndIncrementScript atomically verifies a code hash and manages the attempt counter.
// Returns JSON array: ["ok", accountID] | ["mismatch", "" | "exhausted", "" | "not_found", ""]
// ARGV[1]=SHA256 hex hash of the code, ARGV[2]=max_attempts, ARGV[3]=default_ttl_seconds
var verifyAndIncrementScript = redis.NewScript(`
local cjson = cjson
local data = redis.call('GET', KEYS[1])
if not data then
    return cjson.encode({"not_found", ""})
end
local obj = cjson.decode(data)
local max_attempts = tonumber(ARGV[2])
if obj.attempts >= max_attempts then
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
	redis          *cache.RedisClient
	emailSvc       EmailSender
	smsSvc         SMSSender
	credentialRepo accountRepo.CredentialRepository
	logger         *zap.Logger
	codeTTL        time.Duration
	cooldownTTL    time.Duration
	maxAttempts    int
	codeLength     int
	hashPepper     string // optional secret prepended to code before hashing (prevents rainbow tables if Redis is compromised)
}

// VerificationServiceConfig holds optional configuration for VerificationService.
// Zero-valued fields use package defaults.
type VerificationServiceConfig struct {
	CodeTTL     time.Duration // default: verifyCodeTTL
	CooldownTTL time.Duration // default: verifyCooldownTTL
	MaxAttempts int           // default: verifyCodeAttempts
	CodeLength  int           // default: verifyCodeLength
	HashPepper  string        // optional secret prepended to code before hashing
}

// NewVerificationService creates a new verification service instance
func NewVerificationService(
	redis *cache.RedisClient,
	emailSvc EmailSender,
	smsSvc SMSSender,
	credentialRepo accountRepo.CredentialRepository,
	logger *zap.Logger,
) *VerificationService {
	return NewVerificationServiceWithConfig(redis, emailSvc, smsSvc, credentialRepo, logger, VerificationServiceConfig{})
}

// NewVerificationServiceWithConfig creates a new verification service instance with the given config.
// Zero-valued config fields use package defaults.
func NewVerificationServiceWithConfig(
	redis *cache.RedisClient,
	emailSvc EmailSender,
	smsSvc SMSSender,
	credentialRepo accountRepo.CredentialRepository,
	logger *zap.Logger,
	cfg VerificationServiceConfig,
) *VerificationService {
	logger = utility.EnsureLogger(logger)
	svc := &VerificationService{
		redis:          redis,
		emailSvc:       emailSvc,
		smsSvc:         smsSvc,
		credentialRepo: credentialRepo,
		logger:         logger,
		codeTTL:        verifyCodeTTL,
		cooldownTTL:    verifyCooldownTTL,
		maxAttempts:    verifyCodeAttempts,
		codeLength:     verifyCodeLength,
	}
	if cfg.CodeTTL > 0 {
		svc.codeTTL = cfg.CodeTTL
	}
	if cfg.CooldownTTL > 0 {
		svc.cooldownTTL = cfg.CooldownTTL
	}
	if cfg.MaxAttempts > 0 {
		svc.maxAttempts = cfg.MaxAttempts
	}
	if cfg.CodeLength > 0 {
		svc.codeLength = cfg.CodeLength
	}
	if cfg.HashPepper != "" {
		svc.hashPepper = cfg.HashPepper
	} else {
		svc.logger.Warn("Verification code hash pepper not configured; codes are stored with plain SHA-256. " +
			"Set auth.verify_hash_pepper (env GOUNO_AUTH_VERIFY_HASH_PEPPER) to enable HMAC-based hashing.")
	}
	return svc
}

type verifyCodeData struct {
	CodeHash  string `json:"code"`
	Attempts  int    `json:"attempts"`
	AccountID string `json:"account_id"`
}

// SendCode sends verification code
func (s *VerificationService) SendCode(ctx context.Context, credType, identifier, accountID string) error {
	// Normalize identifier to prevent different casings from creating separate cooldown/code keys
	identifier = strings.ToLower(strings.TrimSpace(identifier))

	// Check cooldown (fail-closed: if Redis is down, deny the request to prevent
	// SMS/email flooding during a Redis outage — consistent with PasswordResetService).
	cooldownKey := s.buildCooldownKey(credType, identifier)
	exists, err := s.redis.Exists(ctx, cooldownKey)
	if err != nil {
		s.logger.Error("Failed to check cooldown, denying request", zap.Error(err))
		return ErrServiceUnavailable
	}
	if exists {
		utility.DummyWorkWithContext(ctx)
		return fmt.Errorf("%w: please wait before requesting another code", ErrCooldownActive)
	}

	// Generate 6-digit random numeric code
	code, err := generateNumericCode(s.codeLength)
	if err != nil {
		return fmt.Errorf("generate code: %w", err)
	}

	// Store in Redis BEFORE sending. If send fails, the code is rolled back
	// to avoid leaving an orphaned code that the user cannot verify.
	// The code is stored as its HMAC hash (using the application pepper as key)
	// so that a Redis compromise does not expose active verification codes.
	// Without the pepper, an attacker cannot precompute a rainbow table even
	// for the small 6-digit numeric keyspace.
	codeHash, err := s.pepperHash(code)
	if err != nil {
		return err
	}
	data := verifyCodeData{
		CodeHash:  codeHash,
		Attempts:  0,
		AccountID: accountID,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal code data: %w", err)
	}

	codeKey := s.buildCodeKey(credType, identifier)
	if err := s.redis.Set(ctx, codeKey, jsonData, s.codeTTL); err != nil {
		return fmt.Errorf("store code: %w", err)
	}

	// Set cooldown (fail-open: if Redis is down, we lose cooldown but can still verify)
	if err := s.redis.Set(ctx, cooldownKey, []byte("1"), s.cooldownTTL); err != nil {
		s.logger.Warn("Failed to set cooldown", zap.Error(err))
	}

	// Send the code. If sending fails, roll back the stored code to avoid
	// leaving an unverifiable code in Redis.
	switch credType {
	case "email":
		if err := s.emailSvc.SendVerificationCode(ctx, identifier, code); err != nil {
			if delErr := s.redis.Del(ctx, codeKey); delErr != nil {
				s.logger.Warn("Failed to rollback stored code after email send failure", zap.Error(delErr))
			}
			return fmt.Errorf("send email: %w", err)
		}
	case "phone":
		if err := s.smsSvc.SendVerificationCode(ctx, identifier, code); err != nil {
			if delErr := s.redis.Del(ctx, codeKey); delErr != nil {
				s.logger.Warn("Failed to rollback stored code after SMS send failure", zap.Error(delErr))
			}
			return fmt.Errorf("send SMS: %w", err)
		}
	default:
		if delErr := s.redis.Del(ctx, codeKey); delErr != nil {
			s.logger.Warn("Failed to rollback stored code for unsupported type", zap.Error(delErr))
		}
		return fmt.Errorf("%w: %s", ErrUnsupportedType, credType)
	}

	s.logger.Info("Verification code sent",
		zap.String("type", credType),
		zap.String("identifier", utility.MaskIdentifier(credType, identifier)))
	return nil
}

// VerifyCode verifies verification code, returns accountID upon success.
// The input code is hashed with SHA-256 before comparison against the stored hash.
func (s *VerificationService) VerifyCode(ctx context.Context, credType, identifier, code string) (string, error) {
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	codeKey := s.buildCodeKey(credType, identifier)

	// Hash the input code with the application pepper before comparison
	codeHash, err := s.pepperHash(code)
	if err != nil {
		return "", err
	}

	// Atomically verify code hash and increment attempts
	resultJSON, err := s.redis.RunScript(ctx, verifyAndIncrementScript, []string{codeKey},
		codeHash, s.maxAttempts, int(s.codeTTL.Seconds())).Result()
	if err != nil {
		// Distinguish Redis infrastructure errors from "code not found" (redis.Nil).
		// Redis connection failures should return ErrServiceUnavailable so callers
		// can return 503 instead of 400 "invalid code".
		if !errors.Is(err, redis.Nil) {
			s.logger.Error("Redis error during verification code check", zap.Error(err))
			return "", ErrServiceUnavailable
		}
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
		return "", ErrVerificationCodeExpired
	case "exhausted":
		return "", ErrVerificationCodeExhausted
	case "mismatch":
		return "", ErrVerificationCodeInvalid
	default:
		return "", fmt.Errorf("unknown verify status: %s", result[0])
	}
}

func (s *VerificationService) buildCodeKey(credType, identifier string) string {
	return fmt.Sprintf("%s%s:%s", verifyCodeKeyPrefix, credType, identifier)
}

func (s *VerificationService) buildCooldownKey(credType, identifier string) string {
	return fmt.Sprintf("%s%s:%s", verifyCooldownPrefix, credType, identifier)
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

// RequireHashPepper returns an error if no hash pepper is configured.
// Call this during startup for production deployments to prevent verification
// codes from being stored with plain SHA-256 (vulnerable to rainbow tables
// on the 6-digit numeric keyspace if Redis is compromised).
func (s *VerificationService) RequireHashPepper() error {
	if s.hashPepper == "" {
		return fmt.Errorf("hash pepper is required for production deployments: " +
			"set auth.verify_hash_pepper (env GOUNO_AUTH_VERIFY_HASH_PEPPER)")
	}
	return nil
}

// pepperHash returns the hex-encoded HMAC-SHA-256 hash of the input string,
// keyed with the application pepper if configured. The pepper prevents
// precomputation attacks (rainbow tables) against the stored hashes.
// Returns an error if the pepper is empty — the pepper MUST be set at construction
// time via HashPepper; without it, HMAC with an empty key reduces to plain SHA-256,
// which is trivially precomputable for the small 6-digit numeric keyspace.
func (s *VerificationService) pepperHash(code string) (string, error) {
	if s.hashPepper == "" {
		return "", fmt.Errorf("verification_service: hashPepper is empty; " +
			"set auth.verify_hash_pepper (env GOUNO_AUTH_VERIFY_HASH_PEPPER) " +
			"to a 64-char hex string (32 bytes)")
	}
	mac := hmac.New(sha256.New, []byte(s.hashPepper))
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ValidateCredentialOwnership checks that the given identifier belongs to the specified account.
// Returns nil if ownership is confirmed, an error otherwise.
func (s *VerificationService) ValidateCredentialOwnership(ctx context.Context, accountID, credType, identifier string) error {
	// Normalize identifier to match SendCode's normalization
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	creds, err := s.credentialRepo.FindByAccountAndType(ctx, accountID, accountDomain.CredentialType(credType))
	if err != nil {
		return fmt.Errorf("lookup credentials: %w", err)
	}
	for _, cred := range creds {
		if cred.Identifier != nil && strings.EqualFold(*cred.Identifier, identifier) {
			return nil
		}
	}
	return ErrIdentifierNotAssociated
}

// VerifyCodeForAccount verifies a code and checks that it belongs to the expected account.
func (s *VerificationService) VerifyCodeForAccount(ctx context.Context, credType, identifier, code, expectedAccountID string) error {
	accountID, err := s.VerifyCode(ctx, credType, identifier, code)
	if err != nil {
		return err
	}
	if accountID != expectedAccountID {
		return ErrVerificationCodeMismatch
	}
	return nil
}
