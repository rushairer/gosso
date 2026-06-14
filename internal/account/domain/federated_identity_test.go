package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFederatedIdentity_WithProfile(t *testing.T) {
	profile := map[string]interface{}{
		"name":  "Test User",
		"email": "test@example.com",
	}
	fi, _ := NewFederatedIdentity("acc-1", ProviderGoogle, "google-123", profile)
	assert.NotEmpty(t, fi.ID)
	assert.Equal(t, "acc-1", fi.AccountID)
	assert.Equal(t, ProviderGoogle, fi.Provider)
	assert.Equal(t, "google-123", fi.ProviderUserID)
	assert.Equal(t, "Test User", fi.Profile["name"])
	assert.False(t, fi.CreatedAt.IsZero())
	assert.False(t, fi.UpdatedAt.IsZero())
}

func TestNewFederatedIdentity_NilProfile(t *testing.T) {
	fi, _ := NewFederatedIdentity("acc-2", ProviderGitHub, "gh-456", nil)
	assert.NotNil(t, fi.Profile)
	assert.Empty(t, fi.Profile)
}

func TestFederatedIdentity_IsDeleted_SoftDelete(t *testing.T) {
	fi, _ := NewFederatedIdentity("acc-3", ProviderWeChat, "wx-789", nil)
	assert.False(t, fi.IsDeleted())
	err := fi.SoftDelete()
	assert.NoError(t, err)
	assert.True(t, fi.IsDeleted())
	assert.NotNil(t, fi.DeletedAt)
}

func TestFederatedIdentity_SoftDelete_DoubleDelete(t *testing.T) {
	fi, _ := NewFederatedIdentity("acc-3", ProviderWeChat, "wx-789", nil)
	err := fi.SoftDelete()
	assert.NoError(t, err)
	err = fi.SoftDelete()
	assert.ErrorIs(t, err, ErrFederatedIdentityAlreadyDeleted)
}

func TestFederatedIdentity_UpdateProfile(t *testing.T) {
	fi, _ := NewFederatedIdentity("acc-4", ProviderGoogle, "g-101", nil)
	oldUpdatedAt := fi.UpdatedAt
	newProfile := map[string]interface{}{"name": "Updated"}
	fi.UpdateProfile(newProfile)
	assert.Equal(t, "Updated", fi.Profile["name"])
	assert.True(t, fi.UpdatedAt.After(oldUpdatedAt) || fi.UpdatedAt.Equal(oldUpdatedAt))
}
