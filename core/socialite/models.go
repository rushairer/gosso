package socialite

import (
	"encoding/json"
	"time"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/rushairer/goth-providers/wechat"
)

type SupportedSocialiteProvider string

const (
	SUPPORTED_SOCIALITE_PROVIDER_WECHAT SupportedSocialiteProvider = "wechat"
	SUPPORTED_SOCIALITE_PROVIDER_GITHUB SupportedSocialiteProvider = "github"
	SUPPORTED_SOCIALITE_PROVIDER_APPLE  SupportedSocialiteProvider = "apple"
)

type SocialiteProviderGithubConfig struct {
	ClientKey   string   `json:"client_key"`
	Secret      string   `json:"secret"`
	CallbackURL string   `json:"callback_url"`
	Scopes      []string `json:"scopes"`
}

type SocialiteProviderWechatConfig struct {
	ClientId     string                `json:"client_id"`
	ClientSecret string                `json:"client_secret"`
	RedirectURL  string                `json:"redirect_url"`
	Lang         wechat.WechatLangType `json:"lang"`
}

type SocialiteProvider struct {
	Id        int64                      `json:"id" db:"id"`
	Name      string                     `json:"name" db:"name"`
	Provider  SupportedSocialiteProvider `json:"provider" db:"provider"`
	Config    string                     `json:"config" db:"config"`
	CreatedAt time.Time                  `json:"-" db:"created_at"`
	UpdatedAt time.Time                  `json:"-" db:"updated_at"`
}

func (p *SocialiteProvider) GothProvider() goth.Provider {
	var provider goth.Provider

	if p.Provider == SUPPORTED_SOCIALITE_PROVIDER_GITHUB {
		config := &SocialiteProviderGithubConfig{}
		if err := json.Unmarshal([]byte(p.Config), config); err == nil {
			provider = github.New(
				config.ClientKey,
				config.Secret,
				config.CallbackURL,
				config.Scopes...,
			)
		}
	} else if p.Provider == SUPPORTED_SOCIALITE_PROVIDER_WECHAT {
		config := &SocialiteProviderWechatConfig{}
		if err := json.Unmarshal([]byte(p.Config), config); err == nil {
			provider = wechat.New(
				config.ClientId,
				config.ClientSecret,
				config.RedirectURL,
				config.Lang,
			)
		}
	}

	return provider
}
