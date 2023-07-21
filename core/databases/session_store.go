package databases

import (
	"net/http"

	"github.com/gorilla/sessions"
)

type SessionStore struct {
	sessionName   string
	sessionSecret string
	store         *sessions.CookieStore
}

func NewSessionStore(sessionName string, sessionSecret string) *SessionStore {
	cookieStore := sessions.NewCookieStore([]byte(sessionSecret))
	cookieStore.Options.HttpOnly = true

	return &SessionStore{
		sessionName:   sessionName,
		sessionSecret: sessionSecret,
		store:         cookieStore,
	}
}

func (ss *SessionStore) Session(r *http.Request) (*sessions.Session, error) {
	return ss.store.Get(r, ss.sessionName)
}
