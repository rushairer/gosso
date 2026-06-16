package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConsent_Success(t *testing.T) {
	consent, err := NewConsent("account-001", "client-001", []string{"openid", "profile"})
	require.NoError(t, err)
	assert.NotEmpty(t, consent.ID)
	assert.Equal(t, "account-001", consent.AccountID)
	assert.Equal(t, "client-001", consent.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, consent.Scopes)
	assert.False(t, consent.CreatedAt.IsZero())
	assert.False(t, consent.UpdatedAt.IsZero())
}

func TestNewConsent_EmptyAccountID(t *testing.T) {
	_, err := NewConsent("", "client-001", []string{"openid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "account_id is required")
}

func TestNewConsent_EmptyClientID(t *testing.T) {
	_, err := NewConsent("account-001", "", []string{"openid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client_id is required")
}

func TestNewConsent_NilScopes(t *testing.T) {
	consent, err := NewConsent("account-001", "client-001", nil)
	require.NoError(t, err)
	assert.NotNil(t, consent.Scopes)
	assert.Empty(t, consent.Scopes)
}

func TestNewConsent_EmptyScopes(t *testing.T) {
	consent, err := NewConsent("account-001", "client-001", []string{})
	require.NoError(t, err)
	assert.Empty(t, consent.Scopes)
}
