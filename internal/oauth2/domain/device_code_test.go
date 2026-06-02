package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeviceCode_IsExpired_NotExpired(t *testing.T) {
	dc := &DeviceCode{
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	assert.False(t, dc.IsExpired())
}

func TestDeviceCode_IsExpired_Expired(t *testing.T) {
	dc := &DeviceCode{
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	assert.True(t, dc.IsExpired())
}

func TestDeviceCode_IsPending_Pending(t *testing.T) {
	dc := &DeviceCode{
		Status: DeviceCodeStatusPending,
	}
	assert.True(t, dc.IsPending())
}

func TestDeviceCode_IsPending_Authorized(t *testing.T) {
	dc := &DeviceCode{
		Status: DeviceCodeStatusAuthorized,
	}
	assert.False(t, dc.IsPending())
}

func TestDeviceCode_IsPending_Denied(t *testing.T) {
	dc := &DeviceCode{
		Status: DeviceCodeStatusDenied,
	}
	assert.False(t, dc.IsPending())
}

func TestDeviceCode_IsPending_Used(t *testing.T) {
	dc := &DeviceCode{
		Status: DeviceCodeStatusUsed,
	}
	assert.False(t, dc.IsPending())
}
