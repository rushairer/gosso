package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
	tokenDomain "github.com/rushairer/gosso/internal/token/domain"
	"github.com/rushairer/gosso/utility"
)

const (
	DeviceCodeKeyPrefix = "device_code:"
	UserCodeKeyPrefix   = "user_code:"
	DeviceCodeLength    = 32 // bytes → 64 hex chars
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
	dcBytes := make([]byte, DeviceCodeLength)
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
	dc := &domain.DeviceCode{
		DeviceCode: deviceCodeStr,
		UserCode:   formattedUserCode,
		ClientID:   clientID,
		Scopes:     scopes,
		Status:     domain.DeviceCodeStatusPending,
		ExpiresAt:  now.Add(s.expiry),
		LastPollAt: time.Time{},
		Interval:   int(s.interval.Seconds()),
	}

	data, err := json.Marshal(dc)
	if err != nil {
		return nil, fmt.Errorf("marshal device code: %w", err)
	}

	// Store device code and user code mapping atomically
	dcHash := tokenDomain.HashToken(deviceCodeStr)
	dcKey := DeviceCodeKeyPrefix + dcHash
	ucKey := UserCodeKeyPrefix + strings.ToUpper(formattedUserCode)
	ttlSeconds := int(s.expiry.Seconds())
	if err := createDeviceCodeScript.Run(ctx, s.redis.GetClient(),
		[]string{dcKey, ucKey},
		string(data), ttlSeconds, dcHash,
	).Err(); err != nil {
		return nil, fmt.Errorf("store device code: %w", err)
	}

	s.logger.Info("Device code created",
		zap.String("client_id", clientID),
		zap.String("user_code", formattedUserCode))

	return dc, nil
}

// GetDeviceCode retrieves a device code by its device_code value.
func (s *DeviceCodeService) GetDeviceCode(ctx context.Context, deviceCode string) (*domain.DeviceCode, error) {
	key := DeviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)
	data, err := s.redis.Get(ctx, key)
	if err == cache.ErrKeyNotFound {
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

	ucKey := UserCodeKeyPrefix + formatted
	dcHash, err := s.redis.Get(ctx, ucKey)
	if err == cache.ErrKeyNotFound {
		return nil, domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve user code: %w", err)
	}

	dcKey := DeviceCodeKeyPrefix + dcHash
	data, err := s.redis.Get(ctx, dcKey)
	if err == cache.ErrKeyNotFound {
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

// AuthorizeDeviceCode atomically marks a device code as authorized with the given account ID.
func (s *DeviceCodeService) AuthorizeDeviceCode(ctx context.Context, deviceCode, accountID string) error {
	key := DeviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)

	remaining, err := s.redis.TTL(ctx, key)
	if err != nil {
		return fmt.Errorf("get device code ttl: %w", err)
	}
	if remaining <= 0 {
		return domain.ErrDeviceCodeNotFound
	}

	authorizedAt := time.Now().Format(time.RFC3339)
	result, err := authorizeDeviceCodeScript.Run(ctx, s.redis.GetClient(), []string{key},
		accountID, authorizedAt, fmt.Sprintf("%d", int(remaining.Seconds())),
	).Result()
	if err == redis.Nil || result == nil {
		return domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("authorize device code: %w", err)
	}

	s.logger.Info("Device code authorized",
		zap.String("account_id", accountID))
	return nil
}

// DenyDeviceCode atomically marks a device code as denied.
func (s *DeviceCodeService) DenyDeviceCode(ctx context.Context, deviceCode string) error {
	key := DeviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)

	remaining, err := s.redis.TTL(ctx, key)
	if err != nil {
		return fmt.Errorf("get device code ttl: %w", err)
	}
	if remaining <= 0 {
		return domain.ErrDeviceCodeNotFound
	}

	result, err := denyDeviceCodeScript.Run(ctx, s.redis.GetClient(), []string{key},
		fmt.Sprintf("%d", int(remaining.Seconds())),
	).Result()
	if err == redis.Nil || result == nil {
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
		zap.String("user_code", dc.UserCode))
	return nil
}

// checkAndUpdatePollRateScript atomically checks the poll interval and updates LastPollAt.
// KEYS[1] = device code key
// ARGV[1] = TTL in seconds
// ARGV[2] = current epoch seconds (integer)
// ARGV[3] = interval in seconds
// Returns 1 if poll allowed, 0 if too fast (slow down), nil if not found.
var checkAndUpdatePollRateScript = redis.NewScript(`
local cjson = require('cjson')
local data = redis.call('GET', KEYS[1])
if not data then
    return nil
end
local dc = cjson.decode(data)
local now = tonumber(ARGV[2])
local interval = tonumber(ARGV[3])
local lastEpoch = dc._last_poll_epoch or 0
if lastEpoch > 0 and (now - lastEpoch) < interval then
    return 0
end
dc._last_poll_epoch = now
dc.last_poll_at = os.date("!%Y-%m-%dT%H:%M:%SZ", now)
local updated = cjson.encode(dc)
redis.call('SET', KEYS[1], updated, 'EX', ARGV[1])
return 1
`)

// CheckAndUpdatePollRate enforces the minimum polling interval.
// Returns ErrSlowDown if the client polls too fast.
func (s *DeviceCodeService) CheckAndUpdatePollRate(ctx context.Context, deviceCode string) error {
	key := DeviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)

	remaining, err := s.redis.TTL(ctx, key)
	if err != nil {
		return fmt.Errorf("get device code ttl: %w", err)
	}
	if remaining <= 0 {
		return domain.ErrDeviceCodeNotFound
	}

	now := time.Now().Unix()
	result, err := checkAndUpdatePollRateScript.Run(ctx, s.redis.GetClient(), []string{key},
		fmt.Sprintf("%d", int(remaining.Seconds())),
		fmt.Sprintf("%d", now),
		fmt.Sprintf("%d", int(s.interval.Seconds())),
	).Result()
	if err == redis.Nil || result == nil {
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
redis.call('SET', KEYS[1], updated, 'EX', ARGV[3])
return updated
`)

// denyDeviceCodeScript atomically checks pending status and sets denied.
// KEYS[1] = device code key
// ARGV[1] = TTL seconds
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
redis.call('SET', KEYS[1], updated, 'EX', ARGV[1])
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
// Returns the JSON data if the transition succeeded, or nil if the status was not "authorized".
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
// Returns the device code data if the claim succeeded, or an error if the code is not in authorized state.
// This prevents double-use race conditions.
func (s *DeviceCodeService) ClaimAuthorizedDeviceCode(ctx context.Context, deviceCode string) (*domain.DeviceCode, error) {
	key := DeviceCodeKeyPrefix + tokenDomain.HashToken(deviceCode)

	result, err := claimAuthorizedScript.Run(ctx, s.redis.GetClient(), []string{key}).Result()
	if err == redis.Nil || result == nil {
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
