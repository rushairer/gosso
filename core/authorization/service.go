package authorization

import (
	"context"
	"database/sql"

	"github.com/markbates/goth"
)

type AuthorizationService struct {
	db             *sql.DB
	userRepository *UserRepository
}

func NewAuthorizationService(db *sql.DB) *AuthorizationService {
	userRepository := NewUserRepository(db)
	return &AuthorizationService{
		db:             db,
		userRepository: userRepository,
	}
}

func (s *AuthorizationService) SaveUser(ctx context.Context, user goth.User) (err error) {
	// TODO: save user
	return
}
