package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	AuthCodeKeyPrefix = "auth_code:"
	AuthCodeLength    = 32
)

// AuthCodeService handles authorization codes (stored in Redis)
type AuthCodeService struct {
	redis  *cache.RedisClient
	logger *zap.Logger
	expiry time.Duration
}

// NewAuthCodeService creates a new authorization code service instance
func NewAuthCodeService(redis *cache.RedisClient, logger *zap.Logger, expiry time.Duration) *AuthCodeService {
	logger = utility.EnsureLogger(logger)
	return &AuthCodeService{
		redis:  redis,
		logger: logger,
		expiry: expiry,
	}
}

// GenerateCode generates an authorization code and stores it in Redis
func (s *AuthCodeService) GenerateCode(
	ctx context.Context,
	clientID, accountID, redirectURI string,
	scopes []string,
	codeChallenge, codeChallengeMethod, nonce string,
) (*domain.AuthorizationCode, error) {
	bytes := make([]byte, AuthCodeLength)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("generate random code: %w", err)
	}
	codeString := hex.EncodeToString(bytes)

	now := time.Now()
	ac, err := domain.NewAuthorizationCode(codeString, clientID, accountID, redirectURI, scopes, now.Add(s.expiry), now)
	if err != nil {
		return nil, fmt.Errorf("create authorization code: %w", err)
	}
	ac.CodeChallenge = codeChallenge
	ac.CodeChallengeMethod = codeChallengeMethod
	ac.Nonce = nonce

	// Clear the plaintext code before storing in Redis — only the hash is used as the key.
	// The raw code is returned to the caller but never persisted.
	storedCode := *ac
	storedCode.Code = ""

	data, err := json.Marshal(storedCode)
	if err != nil {
		return nil, fmt.Errorf("marshal authorization code: %w", err)
	}

	key := AuthCodeKeyPrefix + tokenDomain.HashToken(codeString)
	if err := s.redis.Set(ctx, key, data, s.expiry); err != nil {
		return nil, fmt.Errorf("store authorization code: %w", err)
	}

	s.logger.Debug("Authorization code generated",
		zap.String("client_id", clientID),
		zap.String("account_id", accountID))

	return ac, nil
}

// getAndDeleteScript atomically retrieves and deletes an authorization code in a single Redis operation.
// This prevents TOCTOU race conditions that would allow an authorization code to be used twice.
var getAndDeleteScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if data then
    redis.call('DEL', KEYS[1])
end
return data
`)

// ValidateCode validates an authorization code, checks PKCE, then deletes it (single use).
// The get+delete is performed atomically via a Redis Lua script to prevent double-use race conditions.
func (s *AuthCodeService) ValidateCode(ctx context.Context, code, clientID, redirectURI string, codeVerifier *string) (*domain.AuthorizationCode, error) {
	key := AuthCodeKeyPrefix + tokenDomain.HashToken(code)

	// Atomically GET + DELETE the authorization code
	result, err := s.redis.RunScript(ctx, getAndDeleteScript, []string{key}).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return nil, domain.ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get authorization code: %w", err)
	}

	dataStr, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected authorization code data type")
	}

	var ac domain.AuthorizationCode
	if err := json.Unmarshal([]byte(dataStr), &ac); err != nil {
		return nil, fmt.Errorf("unmarshal authorization code: %w", err)
	}

	if ac.IsExpired() {
		return nil, domain.ErrCodeExpired
	}
	if ac.ClientID != clientID {
		return nil, domain.ErrCodeClientMismatch
	}
	if ac.RedirectURI != redirectURI {
		return nil, domain.ErrCodeURIMismatch
	}

	// PKCE verification: if a code_challenge was set during authorization,
	// the code_verifier MUST be provided and validated (RFC 7636).
	if ac.CodeChallenge != "" {
		if codeVerifier == nil || !ac.VerifyPKCE(*codeVerifier) {
			return nil, domain.ErrPKCEVerificationFailed
		}
	}

	return &ac, nil
}
