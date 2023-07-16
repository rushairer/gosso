package socialite

import (
	"context"
	"database/sql"

	"github.com/markbates/goth"
)

type SocialiteService struct {
	db                  *sql.DB
	socialiteRepository *SocialiteRepository
}

func NewSocialiteService(db *sql.DB) *SocialiteService {
	socialiteRepository := NewSocialiteRepository(db)

	return &SocialiteService{
		db:                  db,
		socialiteRepository: socialiteRepository,
	}
}

func (s *SocialiteService) UseProviders(ctx context.Context) (err error) {

	socialiteProviders, err := s.socialiteRepository.GetSocialiteProviderList(ctx, SOCIALITE_PROVIDER_STATUS_NORMAL)

	var providers []goth.Provider
	for _, socialiteProvider := range socialiteProviders {
		if gothProvider, err := socialiteProvider.GothProvider(); err == nil {
			providers = append(providers, gothProvider)
		}
	}

	goth.UseProviders(providers...)
	return
}
