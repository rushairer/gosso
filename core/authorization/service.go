package authorization

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/rushairer/gosso/core/databases"
)

type AuthorizationService struct {
	db             *sql.DB
	sessionStore   *databases.SessionStore
	userRepository *UserRepository
}

func NewAuthorizationService(db *sql.DB, sessionStore *databases.SessionStore) *AuthorizationService {
	userRepository := NewUserRepository(db)
	return &AuthorizationService{
		db:             db,
		sessionStore:   sessionStore,
		userRepository: userRepository,
	}
}

func (s *AuthorizationService) SaveUser(ctx *gin.Context, gothUser goth.User) error {
	var user User
	var err error
	connectedAccount, err := s.userRepository.GetConnectedAccount(ctx, gothUser.Provider, gothUser.UserID)
	if err != nil {
		if err.Error() == sql.ErrNoRows.Error() {
			connectedAccount, err = NewConnectedAccountFromGothUser(gothUser)
			if err != nil {
				return err
			}

			userId, err := s.userRepository.CreateAccountWithConnectedAccount(ctx, connectedAccount)
			if err != nil {
				return err
			}

			connectedAccount.UserId = userId
		} else {
			return err
		}
	}

	user, err = s.userRepository.GetUserWithDetailById(ctx, connectedAccount.UserId)
	if err != nil {
		return err
	}

	err = s.saveUserIntoSession(ctx.Writer, ctx.Request, user)
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthorizationService) saveUserIntoSession(w http.ResponseWriter, r *http.Request, user User) error {
	if session, err := s.sessionStore.Session(r); err == nil {
		if data, err := json.Marshal(user); err == nil {
			session.Values["user"] = data
			return session.Save(r, w)
		} else {
			return err
		}
	} else {
		log.Println("save user session error", err, user)
		session.Values = nil
		session.Save(r, w)
		return err
	}
}
