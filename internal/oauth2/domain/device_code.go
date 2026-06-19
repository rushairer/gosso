package domain

import (
	"errors"
	"time"
)

// ErrDeviceCodeNotFound is returned when a device code does not exist.
var ErrDeviceCodeNotFound = errors.New("device code not found")

// DeviceCode domain sentinel errors.
var (
	ErrDeviceCodeRequired          = errors.New("device code: device_code is required")
	ErrUserCodeRequired            = errors.New("device code: user_code is required")
	ErrDeviceClientRequired        = errors.New("device code: client_id is required")
	ErrDeviceExpiresRequired       = errors.New("device code: expires_at is required")
	ErrDeviceCodeAlreadyAuthorized = errors.New("device code: already authorized")
	ErrDeviceCodeAlreadyDenied     = errors.New("device code: already denied")
	ErrDeviceCodeAlreadyUsed       = errors.New("device code: already used")
	ErrDeviceCodeNotAuthorized     = errors.New("device code: not authorized")
)

// NewDeviceCode creates a new DeviceCode with the required fields.
// Validates that deviceCode, userCode, clientID are non-empty and expiresAt is not zero.
func NewDeviceCode(deviceCode, userCode, clientID string, scopes []string, expiresAt time.Time, interval int) (*DeviceCode, error) {
	if deviceCode == "" {
		return nil, ErrDeviceCodeRequired
	}
	if userCode == "" {
		return nil, ErrUserCodeRequired
	}
	if clientID == "" {
		return nil, ErrDeviceClientRequired
	}
	if expiresAt.IsZero() {
		return nil, ErrDeviceExpiresRequired
	}
	if scopes == nil {
		scopes = []string{}
	}
	return &DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		Status:     DeviceCodeStatusPending,
		ExpiresAt:  expiresAt,
		Interval:   interval,
		CreatedAt:  time.Now(),
	}, nil
}

// DeviceCodeStatus represents the lifecycle state of a device authorization code.
type DeviceCodeStatus string

const (
	DeviceCodeStatusPending    DeviceCodeStatus = "pending"
	DeviceCodeStatusAuthorized DeviceCodeStatus = "authorized"
	DeviceCodeStatusDenied     DeviceCodeStatus = "denied"
	DeviceCodeStatusUsed       DeviceCodeStatus = "used"
)

// DeviceCode represents an OAuth2 Device Authorization Grant code (RFC 8628).
type DeviceCode struct {
	DeviceCode   string           `json:"device_code"`
	UserCode     string           `json:"user_code"`
	ClientID     string           `json:"client_id"`
	AccountID    string           `json:"account_id"`
	Scopes       []string         `json:"scopes"`
	Status       DeviceCodeStatus `json:"status"`
	ExpiresAt    time.Time        `json:"expires_at"`
	AuthorizedAt time.Time        `json:"authorized_at,omitempty"` // When the user authorized the device
	LastPollAt   time.Time        `json:"last_poll_at"`
	Interval     int              `json:"interval"` // Minimum seconds between poll requests
	CreatedAt    time.Time        `json:"created_at"`
	// Hash is the SHA-256 hash of the raw device code, used as the Redis key.
	// It is populated when reading from Redis (via GetDeviceCodeByUserCode) and
	// is NOT serialized to Redis or JSON responses (json:"-").
	Hash string `json:"-"`
}

// IsExpired returns true if the device code has passed its expiration time.
func (d *DeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// IsPending returns true if the device code is still awaiting user authorization.
func (d *DeviceCode) IsPending() bool {
	return d.Status == DeviceCodeStatusPending
}

// Authorize transitions the device code from pending to authorized.
func (d *DeviceCode) Authorize(accountID string) error {
	if d.Status == DeviceCodeStatusAuthorized {
		return ErrDeviceCodeAlreadyAuthorized
	}
	if d.Status == DeviceCodeStatusDenied {
		return ErrDeviceCodeAlreadyDenied
	}
	if d.Status == DeviceCodeStatusUsed {
		return ErrDeviceCodeAlreadyUsed
	}
	d.Status = DeviceCodeStatusAuthorized
	d.AccountID = accountID
	d.AuthorizedAt = time.Now()
	return nil
}

// Deny transitions the device code from pending to denied.
func (d *DeviceCode) Deny() error {
	if d.Status == DeviceCodeStatusAuthorized {
		return ErrDeviceCodeAlreadyAuthorized
	}
	if d.Status == DeviceCodeStatusDenied {
		return ErrDeviceCodeAlreadyDenied
	}
	if d.Status == DeviceCodeStatusUsed {
		return ErrDeviceCodeAlreadyUsed
	}
	d.Status = DeviceCodeStatusDenied
	return nil
}

// MarkUsed transitions the device code from authorized to used.
func (d *DeviceCode) MarkUsed() error {
	if d.Status == DeviceCodeStatusUsed {
		return ErrDeviceCodeAlreadyUsed
	}
	if d.Status != DeviceCodeStatusAuthorized {
		return ErrDeviceCodeNotAuthorized
	}
	d.Status = DeviceCodeStatusUsed
	return nil
}

// Sentinel errors for device code operations.
var (
	ErrDeviceCodeExpired = errors.New("device code expired")
	ErrSlowDown          = errors.New("slow down")
)
