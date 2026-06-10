package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	accountService "github.com/rushairer/gosso/internal/account/service"
)

func newTestUserInfoService(t *testing.T) *UserInfoService {
	t.Helper()

	username := "testuser"
	avatarURL := "https://example.com/avatar.png"
	accountSvc := &mockAccountService{
		accounts: map[string]*accountDomain.Account{
			"account-001": {
				ID:          "account-001",
				Username:    &username,
				DisplayName: "Test User",
				AvatarURL:   &avatarURL,
				Status:      accountDomain.AccountStatusActive,
				Locale:      "zh-CN",
				Timezone:    "Asia/Shanghai",
			},
			"suspended-001": {
				ID:          "suspended-001",
				Username:    strPtr("suspended"),
				DisplayName: "Suspended User",
				Status:      accountDomain.AccountStatusSuspended,
				Locale:      "en",
				Timezone:    "UTC",
			},
		},
	}

	credRepo := &mockCredentialRepo{
		credentials: map[string][]*accountDomain.Credential{
			"account-001:email": {
				{
					ID:         "cred-email-001",
					AccountID:  "account-001",
					Type:       accountDomain.CredentialTypeEmail,
					Identifier: strPtr("test@example.com"),
					Verified:   true,
				},
			},
			"account-001:phone": {
				{
					ID:         "cred-phone-001",
					AccountID:  "account-001",
					Type:       accountDomain.CredentialTypePhone,
					Identifier: strPtr("+8613800138000"),
					Verified:   true,
				},
			},
		},
	}

	return NewUserInfoService(accountSvc, credRepo, zap.NewNop())
}

func TestUserInfo_GetUserInfo_SubOnly(t *testing.T) {
	svc := newTestUserInfoService(t)
	info, err := svc.GetUserInfo(context.Background(), "account-001", []string{"openid"})
	require.NoError(t, err)
	assert.Equal(t, "account-001", info["sub"])
	assert.Nil(t, info["name"])
	assert.Nil(t, info["email"])
}

func TestUserInfo_GetUserInfo_ProfileScope(t *testing.T) {
	svc := newTestUserInfoService(t)
	info, err := svc.GetUserInfo(context.Background(), "account-001", []string{"openid", "profile"})
	require.NoError(t, err)

	assert.Equal(t, "Test User", info["name"])
	assert.Equal(t, "testuser", info["preferred_username"])
	assert.Equal(t, "https://example.com/avatar.png", info["picture"])
	assert.Equal(t, "zh-CN", info["locale"])
}

func TestUserInfo_GetUserInfo_EmailScope(t *testing.T) {
	svc := newTestUserInfoService(t)
	info, err := svc.GetUserInfo(context.Background(), "account-001", []string{"openid", "email"})
	require.NoError(t, err)

	assert.Equal(t, "test@example.com", info["email"])
	assert.Equal(t, true, info["email_verified"])
}

func TestUserInfo_GetUserInfo_PhoneScope(t *testing.T) {
	svc := newTestUserInfoService(t)
	info, err := svc.GetUserInfo(context.Background(), "account-001", []string{"openid", "phone"})
	require.NoError(t, err)

	assert.Equal(t, "+8613800138000", info["phone_number"])
	assert.Equal(t, true, info["phone_number_verified"])
}

func TestUserInfo_GetUserInfo_AllScopes(t *testing.T) {
	svc := newTestUserInfoService(t)
	info, err := svc.GetUserInfo(context.Background(), "account-001", []string{"openid", "profile", "email", "phone"})
	require.NoError(t, err)

	assert.Equal(t, "account-001", info["sub"])
	assert.Equal(t, "Test User", info["name"])
	assert.Equal(t, "test@example.com", info["email"])
	assert.Equal(t, "+8613800138000", info["phone_number"])
}

func TestUserInfo_GetUserInfo_AccountNotFound(t *testing.T) {
	svc := newTestUserInfoService(t)
	_, err := svc.GetUserInfo(context.Background(), "nonexistent", []string{"openid"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "find account")
}

func TestUserInfo_GetUserInfo_AccountNotActive(t *testing.T) {
	svc := newTestUserInfoService(t)
	_, err := svc.GetUserInfo(context.Background(), "suspended-001", []string{"openid"})
	assert.ErrorIs(t, err, accountService.ErrAccountNotActive)
}

func TestUserInfo_GetUserInfo_NoAvatar(t *testing.T) {
	accountSvc := &mockAccountService{
		accounts: map[string]*accountDomain.Account{
			"account-no-avatar": {
				ID:          "account-no-avatar",
				Username:    strPtr("noavatar"),
				DisplayName: "No Avatar",
				Status:      accountDomain.AccountStatusActive,
				Locale:      "en",
				Timezone:    "UTC",
			},
		},
	}
	credRepo := &mockCredentialRepo{credentials: map[string][]*accountDomain.Credential{}}
	svc := NewUserInfoService(accountSvc, credRepo, zap.NewNop())

	info, err := svc.GetUserInfo(context.Background(), "account-no-avatar", []string{"openid", "profile"})
	require.NoError(t, err)
	assert.Nil(t, info["picture"])
}

func TestUserInfo_GetUserInfo_NoEmailCredential(t *testing.T) {
	accountSvc := &mockAccountService{
		accounts: map[string]*accountDomain.Account{
			"account-no-email": {
				ID:          "account-no-email",
				DisplayName: "No Email",
				Status:      accountDomain.AccountStatusActive,
				Locale:      "en",
				Timezone:    "UTC",
			},
		},
	}
	credRepo := &mockCredentialRepo{credentials: map[string][]*accountDomain.Credential{}}
	svc := NewUserInfoService(accountSvc, credRepo, zap.NewNop())

	info, err := svc.GetUserInfo(context.Background(), "account-no-email", []string{"openid", "email"})
	require.NoError(t, err)
	assert.Nil(t, info["email"])
	assert.Nil(t, info["email_verified"])
}

func TestUserInfo_GetUserInfo_NilLogger(t *testing.T) {
	accountSvc := &mockAccountService{accounts: map[string]*accountDomain.Account{}}
	credRepo := &mockCredentialRepo{credentials: map[string][]*accountDomain.Credential{}}
	svc := NewUserInfoService(accountSvc, credRepo, nil)

	_, err := svc.GetUserInfo(context.Background(), "any", []string{"openid"})
	assert.Error(t, err) // account not found, but no panic from nil logger
}

func TestUserInfo_GetUserInfo_CredentialRepoError(t *testing.T) {
	accountSvc := &mockAccountService{
		accounts: map[string]*accountDomain.Account{
			"account-001": {
				ID:          "account-001",
				DisplayName: "Test",
				Status:      accountDomain.AccountStatusActive,
				Locale:      "en",
				Timezone:    "UTC",
			},
		},
	}
	credRepo := &mockCredentialRepo{
		credentials: map[string][]*accountDomain.Credential{
			"account-001:email": {},
		},
		findByAccountAndTypeErr: fmt.Errorf("db error"),
	}
	svc := NewUserInfoService(accountSvc, credRepo, zap.NewNop())

	info, err := svc.GetUserInfo(context.Background(), "account-001", []string{"openid", "email"})
	require.NoError(t, err)
	assert.Nil(t, info["email"])
}
