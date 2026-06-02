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

	"go.uber.org/zap"

	"github.com/rushairer/gosso/internal/cache"
	"github.com/rushairer/gosso/internal/oauth2/domain"
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
	if logger == nil {
		logger = zap.NewNop()
	}
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

	// Store device code → full JSON
	dcKey := DeviceCodeKeyPrefix + deviceCodeStr
	if err := s.redis.Set(ctx, dcKey, data, s.expiry); err != nil {
		return nil, fmt.Errorf("store device code: %w", err)
	}

	// Store user code → device code string (for lookup by user code)
	ucKey := UserCodeKeyPrefix + strings.ToUpper(formattedUserCode)
	if err := s.redis.Set(ctx, ucKey, deviceCodeStr, s.expiry); err != nil {
		return nil, fmt.Errorf("store user code mapping: %w", err)
	}

	s.logger.Info("Device code created",
		zap.String("client_id", clientID),
		zap.String("user_code", formattedUserCode))

	return dc, nil
}

// GetDeviceCode retrieves a device code by its device_code value.
func (s *DeviceCodeService) GetDeviceCode(ctx context.Context, deviceCode string) (*domain.DeviceCode, error) {
	key := DeviceCodeKeyPrefix + deviceCode
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
func (s *DeviceCodeService) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*domain.DeviceCode, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(userCode, "-", ""))
	formatted := normalized[:4] + "-" + normalized[4:]

	ucKey := UserCodeKeyPrefix + formatted
	deviceCode, err := s.redis.Get(ctx, ucKey)
	if err == cache.ErrKeyNotFound {
		return nil, domain.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve user code: %w", err)
	}

	return s.GetDeviceCode(ctx, deviceCode)
}

// AuthorizeDeviceCode marks a device code as authorized with the given account ID.
func (s *DeviceCodeService) AuthorizeDeviceCode(ctx context.Context, deviceCode, accountID string) error {
	dc, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return err
	}

	dc.Status = domain.DeviceCodeStatusAuthorized
	dc.AccountID = accountID

	return s.save(ctx, dc)
}

// DenyDeviceCode marks a device code as denied.
func (s *DeviceCodeService) DenyDeviceCode(ctx context.Context, deviceCode string) error {
	dc, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return err
	}

	dc.Status = domain.DeviceCodeStatusDenied

	return s.save(ctx, dc)
}

// CheckAndUpdatePollRate enforces the minimum polling interval.
// Returns ErrSlowDown if the client polls too fast.
func (s *DeviceCodeService) CheckAndUpdatePollRate(ctx context.Context, deviceCode string) error {
	dc, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return err
	}

	if !dc.LastPollAt.IsZero() && time.Since(dc.LastPollAt) < time.Duration(dc.Interval)*time.Second {
		return domain.ErrSlowDown
	}

	dc.LastPollAt = time.Now()
	return s.save(ctx, dc)
}

// MarkUsed sets the device code status to "used".
func (s *DeviceCodeService) MarkUsed(ctx context.Context, deviceCode string) error {
	dc, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return err
	}

	dc.Status = domain.DeviceCodeStatusUsed

	return s.save(ctx, dc)
}

func (s *DeviceCodeService) save(ctx context.Context, dc *domain.DeviceCode) error {
	data, err := json.Marshal(dc)
	if err != nil {
		return fmt.Errorf("marshal device code: %w", err)
	}

	remaining := time.Until(dc.ExpiresAt)
	if remaining <= 0 {
		remaining = time.Second
	}

	key := DeviceCodeKeyPrefix + dc.DeviceCode
	if err := s.redis.Set(ctx, key, data, remaining); err != nil {
		return fmt.Errorf("save device code: %w", err)
	}

	return nil
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
