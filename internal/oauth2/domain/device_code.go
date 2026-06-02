package domain

import (
	"fmt"
	"time"
)

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
	DeviceCode string           `json:"device_code"`
	UserCode   string           `json:"user_code"`
	ClientID   string           `json:"client_id"`
	AccountID  string           `json:"account_id"`
	Scopes     []string         `json:"scopes"`
	Status     DeviceCodeStatus `json:"status"`
	ExpiresAt  time.Time        `json:"expires_at"`
	LastPollAt time.Time        `json:"last_poll_at"`
	Interval   int              `json:"interval"` // Minimum seconds between poll requests
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
	ErrDeviceCodeNotFound   = fmt.Errorf("device code not found")
	ErrDeviceCodeExpired    = fmt.Errorf("device code expired")
	ErrDeviceCodeDenied     = fmt.Errorf("device code denied")
	ErrDeviceCodeAlreadyUsed = fmt.Errorf("device code already used")
	ErrSlowDown             = fmt.Errorf("slow down")
)
