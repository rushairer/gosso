package domain

import (
	"errors"
	"fmt"
	"time"
)

// ErrDeviceCodeNotFound is returned when a device code does not exist.
var ErrDeviceCodeNotFound = errors.New("device code not found")

// NewDeviceCode creates a new DeviceCode with the required fields.
// Validates that deviceCode, userCode, clientID are non-empty and expiresAt is not zero.
func NewDeviceCode(deviceCode, userCode, clientID string, scopes []string, expiresAt time.Time, interval int) (*DeviceCode, error) {
	if deviceCode == "" {
		return nil, fmt.Errorf("device code: device_code is required")
	}
	if userCode == "" {
		return nil, fmt.Errorf("device code: user_code is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("device code: client_id is required")
	}
	if expiresAt.IsZero() {
		return nil, fmt.Errorf("device code: expires_at is required")
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
}

// IsExpired returns true if the device code has passed its expiration time.
func (d *DeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// IsPending returns true if the device code is still awaiting user authorization.
func (d *DeviceCode) IsPending() bool {
	return d.Status == DeviceCodeStatusPending
}

// Sentinel errors for device code operations.
var (
	ErrDeviceCodeExpired = errors.New("device code expired")
	ErrSlowDown          = errors.New("slow down")
)
