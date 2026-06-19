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

func TestDeviceCode_Authorize_Success(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusPending}
	err := dc.Authorize("account-001")
	assert.NoError(t, err)
	assert.Equal(t, DeviceCodeStatusAuthorized, dc.Status)
	assert.Equal(t, "account-001", dc.AccountID)
	assert.False(t, dc.AuthorizedAt.IsZero())
}

func TestDeviceCode_Authorize_AlreadyAuthorized(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusAuthorized}
	err := dc.Authorize("account-001")
	assert.ErrorIs(t, err, ErrDeviceCodeAlreadyAuthorized)
}

func TestDeviceCode_Authorize_AlreadyDenied(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusDenied}
	err := dc.Authorize("account-001")
	assert.ErrorIs(t, err, ErrDeviceCodeAlreadyDenied)
}

func TestDeviceCode_Authorize_AlreadyUsed(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusUsed}
	err := dc.Authorize("account-001")
	assert.ErrorIs(t, err, ErrDeviceCodeAlreadyUsed)
}

func TestDeviceCode_Deny_Success(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusPending}
	err := dc.Deny()
	assert.NoError(t, err)
	assert.Equal(t, DeviceCodeStatusDenied, dc.Status)
}

func TestDeviceCode_Deny_AlreadyAuthorized(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusAuthorized}
	err := dc.Deny()
	assert.ErrorIs(t, err, ErrDeviceCodeAlreadyAuthorized)
}

func TestDeviceCode_Deny_AlreadyDenied(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusDenied}
	err := dc.Deny()
	assert.ErrorIs(t, err, ErrDeviceCodeAlreadyDenied)
}

func TestDeviceCode_Deny_AlreadyUsed(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusUsed}
	err := dc.Deny()
	assert.ErrorIs(t, err, ErrDeviceCodeAlreadyUsed)
}

func TestDeviceCode_MarkUsed_Success(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusAuthorized}
	err := dc.MarkUsed()
	assert.NoError(t, err)
	assert.Equal(t, DeviceCodeStatusUsed, dc.Status)
}

func TestDeviceCode_MarkUsed_NotAuthorized(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusPending}
	err := dc.MarkUsed()
	assert.ErrorIs(t, err, ErrDeviceCodeNotAuthorized)
}

func TestDeviceCode_MarkUsed_AlreadyUsed(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusUsed}
	err := dc.MarkUsed()
	assert.ErrorIs(t, err, ErrDeviceCodeAlreadyUsed)
}

func TestDeviceCode_MarkUsed_Denied(t *testing.T) {
	dc := &DeviceCode{Status: DeviceCodeStatusDenied}
	err := dc.MarkUsed()
	assert.ErrorIs(t, err, ErrDeviceCodeNotAuthorized)
}
