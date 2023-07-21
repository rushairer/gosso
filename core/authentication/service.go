package authentication

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/rushairer/gosso/core/databases"
)

type AuthenticationService struct {
	db             *sql.DB
	sessionStore   *databases.SessionStore
	userRepository *UserRepository
}

const SESSION_KEY_USER = "user"

func NewAuthenticationService(db *sql.DB, sessionStore *databases.SessionStore) *AuthenticationService {
	userRepository := NewUserRepository(db)
	return &AuthenticationService{
		db:             db,
		sessionStore:   sessionStore,
		userRepository: userRepository,
	}
}

func (s *AuthenticationService) SaveUser(ctx *gin.Context, gothUser goth.User) error {
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

	err = s.SaveUserToSession(ctx.Writer, ctx.Request, user)
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthenticationService) SaveUserToSession(w http.ResponseWriter, r *http.Request, user User) error {
	if session, err := s.sessionStore.Session(r); err == nil {
		if data, err := json.Marshal(user); err == nil {
			session.Values[SESSION_KEY_USER] = data
			return session.Save(r, w)
		} else {
			return err
		}
	} else {
		log.Println("[authentication/service]", "save user session error", err, user)
		session.Values = nil
		session.Save(r, w)
		return err
	}
}

func (s *AuthenticationService) GetUserFromSession(r *http.Request) (User, error) {
	user := User{}
	if session, err := s.sessionStore.Session(r); err == nil {
		if data := session.Values[SESSION_KEY_USER]; data != nil {
			err = json.Unmarshal(data.([]byte), &user)
			return user, err
		}
		return user, errors.New("user session is empty")
	} else {
		log.Println("[authentication/service]", "get user session error", err)
		return user, err
	}
}

func (s *AuthenticationService) DeleteUserFromSession(w http.ResponseWriter, r *http.Request) error {
	if session, err := s.sessionStore.Session(r); err == nil {
		session.Values = nil
		return session.Save(r, w)
	} else {
		log.Println("[Authentication/service]", "delete user session error", err)
		return err
	}
}
