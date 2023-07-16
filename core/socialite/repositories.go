package socialite

import "database/sql"

type SocialiteRepository struct {
	db *sql.DB
}

func NewSocialiteRepository(db *sql.DB) *SocialiteRepository {
	return &SocialiteRepository{
		db: db,
	}
}
