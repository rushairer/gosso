package socialite

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGothProvider(t *testing.T) {
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

	provider := SocialiteProvider{
		Id:       1,
		Name:     "provider",
		Provider: SUPPORTED_SOCIALITE_PROVIDER_GITHUB,
		Status:   SOCIALITE_PROVIDER_STATUS_HIDDEN,
		Config:   string(configString),
	}

	gothProvider, err := provider.GothProvider()
	assert.NoError(t, err)

	assert.NotNil(t, gothProvider)

	providerWithError := SocialiteProvider{
		Id:       1,
		Name:     "provider",
		Provider: SUPPORTED_SOCIALITE_PROVIDER_GITHUB,
		Status:   SOCIALITE_PROVIDER_STATUS_HIDDEN,
		Config:   "",
	}

	gothProviderWithError, err := providerWithError.GothProvider()
	assert.Error(t, err)

	assert.Nil(t, gothProviderWithError)
}
