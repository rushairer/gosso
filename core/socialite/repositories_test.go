package socialite

import (
	"context"
	"testing"
	"time"

	"github.com/rushairer/gosso/core/helper"
	"github.com/stretchr/testify/assert"
)

func TestCreateSocialiteProvider(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	socialiteRepository := NewSocialiteRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	socialiteProvider := SocialiteProvider{
		Name: "test_provider",
	}
	socialiteRepository.DeleteSocialiteProvider(ctx, socialiteProvider)

	savedSocialiteProvider, err := socialiteRepository.CreateSocialiteProvider(ctx, socialiteProvider)

	assert.NoError(t, err)
	assert.NotEmpty(t, savedSocialiteProvider.Id)
	assert.Equal(t, savedSocialiteProvider.CreatedAt, savedSocialiteProvider.UpdatedAt)
	assert.Equal(t, savedSocialiteProvider.Name, socialiteProvider.Name)

	socialiteRepository.DeleteSocialiteProvider(ctx, savedSocialiteProvider)
}

func TestGetSocialiteProvider(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	socialiteRepository := NewSocialiteRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	socialiteProvider := SocialiteProvider{
		Name: "test_provider",
	}
	socialiteRepository.DeleteSocialiteProvider(ctx, socialiteProvider)

	savedSocialiteProvider, err := socialiteRepository.CreateSocialiteProvider(ctx, socialiteProvider)

	assert.NoError(t, err)

	getSocialiteProvider, err := socialiteRepository.GetSocialiteProvider(ctx, savedSocialiteProvider.Id)
	assert.NoError(t, err)
	assert.Equal(t, savedSocialiteProvider.Id, getSocialiteProvider.Id)
	assert.Equal(t, savedSocialiteProvider.Name, getSocialiteProvider.Name)
	assert.Equal(t, savedSocialiteProvider.CreatedAt, getSocialiteProvider.CreatedAt)

	socialiteRepository.DeleteSocialiteProvider(ctx, savedSocialiteProvider)
}

func TestGetSocialiteProviderList(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	socialiteRepository := NewSocialiteRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	socialiteProvider := SocialiteProvider{
		Name:   "test_provider",
		Status: SOCIALITE_PROVIDER_STATUS_NORMAL,
	}
	socialiteRepository.DeleteSocialiteProvider(ctx, socialiteProvider)

	savedSocialiteProvider, err := socialiteRepository.CreateSocialiteProvider(ctx, socialiteProvider)

	assert.NoError(t, err)

	list, err := socialiteRepository.GetSocialiteProviderList(ctx, SOCIALITE_PROVIDER_STATUS_NORMAL)
	assert.NoError(t, err)
	assert.NotEmpty(t, list)

	list, err = socialiteRepository.GetSocialiteProviderList(ctx, SOCIALITE_PROVIDER_STATUS_HIDDEN)
	assert.NoError(t, err)
	assert.Empty(t, list)

	socialiteRepository.DeleteSocialiteProvider(ctx, savedSocialiteProvider)
}

func TestDeleteSocialiteProvider(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	socialiteRepository := NewSocialiteRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	socialiteProvider := SocialiteProvider{
		Name: "test_provider",
	}

	socialiteRepository.DeleteSocialiteProvider(ctx, socialiteProvider)

	savedSocialiteProvider, err := socialiteRepository.CreateSocialiteProvider(ctx, socialiteProvider)
	assert.NoError(t, err)

	err = socialiteRepository.DeleteSocialiteProvider(ctx, savedSocialiteProvider)
	assert.NoError(t, err)
}

func TestSoftDeleteSocialiteProvider(t *testing.T) {
	databaseManager := helper.NewDatabaseManagerDefault()
	socialiteRepository := NewSocialiteRepository(databaseManager.MustGetMysqlClient())
	ctx := context.Background()

	socialiteProvider := SocialiteProvider{
		Name: "test_provider",
	}

	socialiteRepository.DeleteSocialiteProvider(ctx, socialiteProvider)

	savedSocialiteProvider, err := socialiteRepository.CreateSocialiteProvider(ctx, socialiteProvider)
	assert.NoError(t, err)

	time.Sleep(2 * time.Second)
	err = socialiteRepository.SoftDeleteSocialiteProvider(ctx, savedSocialiteProvider)
	assert.NoError(t, err)

	getSocialiteProvider, err := socialiteRepository.GetSocialiteProvider(ctx, savedSocialiteProvider.Id)
	assert.NoError(t, err)
	assert.NotNil(t, getSocialiteProvider.DeletedAt)
	assert.NotEqual(t, savedSocialiteProvider.UpdatedAt, getSocialiteProvider.UpdatedAt)

	socialiteRepository.DeleteSocialiteProvider(ctx, savedSocialiteProvider)
}
