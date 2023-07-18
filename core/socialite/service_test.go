package socialite

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/rushairer/gosso/core/helper"
	"github.com/stretchr/testify/assert"
)

func TestUseProviders(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	service := NewSocialiteService(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	config := SocialiteProviderGithubConfig{
		ClientKey:   "CLIENT_KEY",
		Secret:      "SECRET",
		CallbackURL: "CALLBACK_URL",
		Scopes: []string{
			"scope1",
			"scope2",
		},
	}

	configString, err := json.Marshal(config)

	assert.NoError(t, err)

	socialiteProvider := SocialiteProvider{
		Name:     "test_provider",
		Provider: SUPPORTED_SOCIALITE_PROVIDER_GITHUB,
		Status:   SOCIALITE_PROVIDER_STATUS_NORMAL,
		Config:   string(configString),
	}
	service.socialiteRepository.DeleteSocialiteProvider(ctx, socialiteProvider)

	savedSocialiteProvider, err := service.socialiteRepository.CreateSocialiteProvider(ctx, socialiteProvider)
	assert.NoError(t, err)
	assert.NotEmpty(t, savedSocialiteProvider.Id)

	err = service.UseProviders(ctx)
	assert.NoError(t, err)

	provider, err := goth.GetProvider(savedSocialiteProvider.Name)
	assert.NoError(t, err)
	assert.NotEmpty(t, provider.Name())
	assert.Equal(t, provider.Name(), savedSocialiteProvider.Name)

	service.socialiteRepository.DeleteSocialiteProvider(ctx, savedSocialiteProvider)

}

func TestInitProvidersData(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	service := NewSocialiteService(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	config := SocialiteProviderGithubConfig{
		ClientKey:   os.Getenv("GITHUB_CLIENT_ID"),
		Secret:      os.Getenv("GITHUB_CLIENT_SECRET"),
		CallbackURL: os.Getenv("GITHUB_CALLBACK_URL"),
		Scopes: []string{
			os.Getenv("GITHUB_SCOPE1"),
			os.Getenv("GITHUB_SCOPE2"),
		},
	}
	configString, err := json.Marshal(config)

	assert.NoError(t, err)

	socialiteProvider := SocialiteProvider{
		Name:     "github_1",
		Provider: SUPPORTED_SOCIALITE_PROVIDER_GITHUB,
		Status:   SOCIALITE_PROVIDER_STATUS_NORMAL,
		Config:   string(configString),
	}
	service.socialiteRepository.DeleteSocialiteProvider(ctx, socialiteProvider)

	savedSocialiteProvider, err := service.socialiteRepository.CreateSocialiteProvider(ctx, socialiteProvider)
	assert.NoError(t, err)
	assert.NotEmpty(t, savedSocialiteProvider.Id)
}
