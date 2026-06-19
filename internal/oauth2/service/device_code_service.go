package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/internal/utility"
)

const (
	deviceCodeKeyPrefix = "device_code:"
	userCodeKeyPrefix   = "user_code:"
	deviceCodeLength    = 32 // bytes → 64 hex chars
)

// userCodeCharset excludes ambiguous characters (0/O, 1/I/L).
const userCodeCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// DeviceCodeService handles OAuth2 Device Authorization codes (stored in Redis).
type DeviceCodeService struct {
	redis    *cache.RedisClient
	logger   *zap.Logger
	expiry   time.Duration
	interval time.Duration
}

// NewDeviceCodeService creates a new device code service instance.
func NewDeviceCodeService(redis *cache.RedisClient, logger *zap.Logger, expiry, interval time.Duration) *DeviceCodeService {
	logger = utility.EnsureLogger(logger)
	if expiry <= 0 {
		expiry = 10 * time.Minute
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &DeviceCodeService{
		redis:    redis,
		logger:   logger,
		expiry:   expiry,
		interval: interval,
	}
}

// CreateDeviceCode generates a device code and user code, stores them in Redis.
func (s *DeviceCodeService) CreateDeviceCode(ctx context.Context, clientID string, scopes []string) (*domain.DeviceCode, error) {
	// Generate device code (32 random bytes → 64 hex chars)
	dcBytes := make([]byte, deviceCodeLength)
	if _, err := rand.Read(dcBytes); err != nil {
		return nil, fmt.Errorf("generate device code: %w", err)
	}
	deviceCodeStr := hex.EncodeToString(dcBytes)

	// Generate user code (XXXX-XXXX format)
	userCode, err := generateUserCode(8)
	if err != nil {
		return nil, fmt.Errorf("generate user code: %w", err)
	}
	if len(userCode) != 8 {
		return nil, fmt.Errorf("unexpected user code length: %d", len(userCode))
	}
	formattedUserCode := userCode[:4] + "-" + userCode[4:]

	now := time.Now()
	dc, err := domain.NewDeviceCode(deviceCodeStr, formattedUserCode, clientID, scopes, now.Add(s.expiry), int(s.interval.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("create device code: %w", err)
	}

	// Clear raw device code before storing to avoid plaintext exposure in Redis.
	// The raw value is only returned to the caller (client device), never persisted.
	storedCode := *dc // shallow copy
	storedCode.DeviceCode = ""
	data, err := json.Marshal(storedCode)
	if err != nil {
		return nil, fmt.Errorf("marshal device code: %w", err)
	}

	// Store device code and user code mapping atomically
	dcHash := tokenDomain.HashToken(deviceCodeStr)
	dcKey := deviceCodeKeyPrefix + dcHash
	ucKey := userCodeKeyPrefix + strings.ToUpper(formattedUserCode)
	ttlSeconds := int(s.expiry.Seconds())
	if err := s.redis.RunScript(ctx, createDeviceCodeScript,
		[]string{dcKey, ucKey},
		string(data), ttlSeconds, dcHash,
	).Err(); err != nil {
		return nil, fmt.Errorf("store device code: %w", err)
	}

	s.logger.Info("Device code created",
		zap.String("client_id", clientID),
		zap.String("user_code_prefix", formattedUserCode[:4]+"****"))

	return dc, nil
}

// GetDeviceCode retrieves a device code by its device_code value.
func (s *DeviceCodeService) GetDeviceCode(ctx context.Context, deviceCode string) (*domain.DeviceCode, error) {
	key := deviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)
	data, err := s.redis.Get(ctx, key)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return nil, domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get device code: %w", err)
	}

	var dc domain.DeviceCode
	if err := json.Unmarshal([]byte(data), &dc); err != nil {
		return nil, fmt.Errorf("unmarshal device code: %w", err)
	}

	return &dc, nil
}

// GetDeviceCodeByUserCode resolves a user code to its device code.
// The user code mapping stores the device code hash (not the raw value).
func (s *DeviceCodeService) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(userCode, "-", ""))
	if len(normalized) != 8 {
		return nil, domain.ErrDeviceCodeNotFound
	}
	formatted := normalized[:4] + "-" + normalized[4:]

	ucKey := userCodeKeyPrefix + formatted
	dcHash, err := s.redis.Get(ctx, ucKey)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return nil, domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve user code: %w", err)
	}

	dcKey := deviceCodeKeyPrefix + dcHash
	data, err := s.redis.Get(ctx, dcKey)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return nil, domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get device code: %w", err)
	}

	var dc domain.DeviceCode
	if err := json.Unmarshal([]byte(data), &dc); err != nil {
		return nil, fmt.Errorf("unmarshal device code: %w", err)
	}
	// Populate the Hash field so callers can reference this device code
	// without needing the raw plaintext device code (which is not stored in Redis).
	dc.Hash = dcHash
	return &dc, nil
}

// AuthorizeDeviceCode atomically marks a device code as authorized with the given account ID.
func (s *DeviceCodeService) AuthorizeDeviceCode(ctx context.Context, deviceCode, accountID string) error {
	key := deviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)

	authorizedAt := time.Now().Format(time.RFC3339)
	result, err := s.redis.RunScript(ctx, authorizeDeviceCodeScript, []string{key},
		accountID, authorizedAt,
	).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("authorize device code: %w", err)
	}

	s.logger.Info("Device code authorized",
		zap.String("account_id", utility.MaskOpaqueID(accountID)))
	return nil
}

// DenyDeviceCode atomically marks a device code as denied.
func (s *DeviceCodeService) DenyDeviceCode(ctx context.Context, deviceCode string) error {
	key := deviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)

	result, err := s.redis.RunScript(ctx, denyDeviceCodeScript, []string{key}).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("deny device code: %w", err)
	}

	// Parse result for audit logging
	var dc domain.DeviceCode
	if data, ok := result.(string); ok {
		if err := json.Unmarshal([]byte(data), &dc); err != nil {
			s.logger.Warn("Failed to unmarshal denied device code for audit log", zap.Error(err))
		}
	}

	s.logger.Info("Device code denied",
		zap.String("client_id", dc.ClientID),
		zap.String("user_code_prefix", safeUserCodePrefix(dc.UserCode)))
	return nil
}

// AuthorizeDeviceCodeByHash atomically marks a device code as authorized using its Redis key hash.
// This is the preferred method when the raw device code is not available (e.g., user code consent flow).
func (s *DeviceCodeService) AuthorizeDeviceCodeByHash(ctx context.Context, dcHash, accountID string) error {
	key := deviceCodeKeyPrefix + dcHash

	authorizedAt := time.Now().Format(time.RFC3339)
	result, err := s.redis.RunScript(ctx, authorizeDeviceCodeScript, []string{key},
		accountID, authorizedAt,
	).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("authorize device code: %w", err)
	}

	s.logger.Info("Device code authorized",
		zap.String("account_id", utility.MaskOpaqueID(accountID)))
	return nil
}

// DenyDeviceCodeByHash atomically marks a device code as denied using its Redis key hash.
// This is the preferred method when the raw device code is not available (e.g., user code consent flow).
func (s *DeviceCodeService) DenyDeviceCodeByHash(ctx context.Context, dcHash string) error {
	key := deviceCodeKeyPrefix + dcHash

	result, err := s.redis.RunScript(ctx, denyDeviceCodeScript, []string{key}).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("deny device code: %w", err)
	}

	// Parse result for audit logging
	var dc domain.DeviceCode
	if data, ok := result.(string); ok {
		if err := json.Unmarshal([]byte(data), &dc); err != nil {
			s.logger.Warn("Failed to unmarshal denied device code for audit log", zap.Error(err))
		}
	}

	s.logger.Info("Device code denied",
		zap.String("client_id", dc.ClientID),
		zap.String("user_code_prefix", safeUserCodePrefix(dc.UserCode)))
	return nil
}

// checkAndUpdatePollRateScript atomically checks the poll interval and updates LastPollAt.
// KEYS[1] = device code key
// KEYS[2] = poll epoch tracking key (separate from domain JSON to avoid polluting stored data)
// ARGV[1] = current epoch seconds (integer)
// ARGV[2] = interval in seconds
// Returns 1 if poll allowed, 0 if too fast (slow down), nil if not found.
var checkAndUpdatePollRateScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local lastEpoch = tonumber(redis.call('GET', KEYS[2]) or '0')
if lastEpoch > 0 and (now - lastEpoch) < interval then
    return 0
end
local pttl = redis.call('PTTL', KEYS[1])
if pttl > 0 then
    redis.call('SET', KEYS[2], now, 'PX', pttl)
else
    redis.call('SET', KEYS[2], now)
end
local cjson = require('cjson')
local dc = cjson.decode(data)
dc.last_poll_at = os.date("!%Y-%m-%dT%H:%M:%SZ", now)
if pttl > 0 then
    redis.call('SET', KEYS[1], cjson.encode(dc), 'PX', pttl)
else
    redis.call('SET', KEYS[1], cjson.encode(dc))
end
return 1
`)

// CheckAndUpdatePollRate enforces the minimum polling interval.
// Returns ErrSlowDown if the client polls too fast.
func (s *DeviceCodeService) CheckAndUpdatePollRate(ctx context.Context, deviceCode string) error {
	key := deviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)
	pollKey := deviceCodeKeyPrefix + "poll:" + tokenDomain.HashToken(deviceCode)

	now := time.Now().Unix()
	result, err := s.redis.RunScript(ctx, checkAndUpdatePollRateScript, []string{key, pollKey},
		fmt.Sprintf("%d", now),
		fmt.Sprintf("%d", int(s.interval.Seconds())),
	).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("check poll rate: %w", err)
	}

	if code, ok := result.(int64); ok && code == 0 {
		return domain.ErrSlowDown
	}

	return nil
}

// authorizeDeviceCodeScript atomically checks pending status and sets authorized.
// KEYS[1] = device code key
// ARGV[1] = accountID, ARGV[2] = authorizedAt (RFC3339), ARGV[3] = TTL seconds
// Returns updated JSON on success, nil if not pending.
// authorizeDeviceCodeScript atomically marks a device code as authorized.
// KEYS[1] = device code key
// ARGV[1] = account ID
// ARGV[2] = authorized_at timestamp
// Returns: updated JSON data, or nil if not found or not pending.
var authorizeDeviceCodeScript = redis.NewScript(`
local cjson = require('cjson')
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
local dc = cjson.decode(data)
if dc.status ~= "pending" then
    return nil
end
dc.status = "authorized"
dc.account_id = ARGV[1]
dc.authorized_at = ARGV[2]
local updated = cjson.encode(dc)
local pttl = redis.call('PTTL', KEYS[1])
if pttl > 0 then
    redis.call('SET', KEYS[1], updated, 'PX', pttl)
else
    redis.call('SET', KEYS[1], updated)
end
return updated
`)

// denyDeviceCodeScript atomically checks pending status and sets denied.
// KEYS[1] = device code key
// Returns updated JSON on success, nil if not pending.
var denyDeviceCodeScript = redis.NewScript(`
local cjson = require('cjson')
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
local dc = cjson.decode(data)
if dc.status ~= "pending" then
    return nil
end
dc.status = "denied"
local updated = cjson.encode(dc)
local pttl = redis.call('PTTL', KEYS[1])
if pttl > 0 then
    redis.call('SET', KEYS[1], updated, 'PX', pttl)
else
    redis.call('SET', KEYS[1], updated)
end
return updated
`)

// createDeviceCodeScript atomically stores device code data and user code mapping.
// KEYS[1] = device code key, KEYS[2] = user code key
// ARGV[1] = device code JSON, ARGV[2] = TTL seconds, ARGV[3] = device code string
var createDeviceCodeScript = redis.NewScript(`
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SET', KEYS[2], ARGV[3], 'EX', ARGV[2])
return 1
`)

// Returns the JSON data if the transition succeeded, or nil if the status was not "authorized"
// or the client_id does not match. ARGV[1] = client_id to verify ownership.
var claimAuthorizedScript = redis.NewScript(`
local cjson = require('cjson')
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
local dc = cjson.decode(data)
if dc.status ~= "authorized" then
    return nil
end
if ARGV[1] ~= '' and dc.client_id ~= ARGV[1] then
    return nil
end
dc.status = "used"
local updated = cjson.encode(dc)
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then
    redis.call('SET', KEYS[1], updated, 'EX', ttl)
else
    redis.call('SET', KEYS[1], updated, 'EX', 60)
end
return updated
`)

// ClaimAuthorizedDeviceCode atomically validates that a device code is authorized and marks it as used.
// The clientID parameter is verified against the stored device code to prevent cross-client claims.
// Returns the device code data if the claim succeeded, or an error if the code is not in authorized state.
// This prevents double-use race conditions.
func (s *DeviceCodeService) ClaimAuthorizedDeviceCode(ctx context.Context, deviceCode string, clientID string) (*domain.DeviceCode, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required for claiming device code")
	}

	key := deviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)

	result, err := s.redis.RunScript(ctx, claimAuthorizedScript, []string{key}, clientID).Result()
	if errors.Is(err, redis.Nil) || result == nil {
		return nil, domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("claim device code: %w", err)
	}

	dataStr, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected device code data type")
	}

	var dc domain.DeviceCode
	if err := json.Unmarshal([]byte(dataStr), &dc); err != nil {
		return nil, fmt.Errorf("unmarshal device code: %w", err)
	}

	return &dc, nil
}

// safeUserCodePrefix returns the first 4 characters masked for safe logging.
// Returns "****" if the user code is too short to safely slice.
func safeUserCodePrefix(userCode string) string {
	if len(userCode) >= 4 {
		return userCode[:4] + "****"
	}
	return "****"
}

func generateUserCode(length int) (string, error) {
	var sb strings.Builder
	sb.Grow(length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeCharset))))
		if err != nil {
			return "", err
		}
		sb.WriteByte(userCodeCharset[n.Int64()])
	}
	return sb.String(), nil
}
