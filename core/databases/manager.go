package databases

import (
	"database/sql"
	"errors"
	"log"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/rushairer/gosso/core/utilities/sshtunnel"
	"golang.org/x/crypto/ssh"
)

var (
	ErrInvalidMysqlClient = errors.New("invalid mysql client")
	ErrInvalidCookieStore = errors.New("invalid cookie store")
)

type DatabaseManager struct {
	mysqlClient *sql.DB
	cookieStore *sessions.CookieStore
}

func NewDatabaseManager(
	mysqlDsn string,
	sessionSecret string,
	sshClient *ssh.Client,
) *DatabaseManager {
	manager := &DatabaseManager{}

	if sshClient != nil {
		mysql.RegisterDialContext("tcp", sshtunnel.NewViaSSHDialer(sshClient).DialTCP)
	}
	if mysqlClient, err := sql.Open("mysql", mysqlDsn); err == nil {
		if err = mysqlClient.Ping(); err == nil {
			manager.mysqlClient = mysqlClient
		} else {
			log.Panicln(err)
		}
	} else {
		log.Panicln(err)
	}

	cookieStore := sessions.NewCookieStore([]byte(sessionSecret))
	cookieStore.Options.HttpOnly = true
	manager.cookieStore = cookieStore

	return manager
}

func (m *DatabaseManager) MustGetMysqlClient() *sql.DB {
	if m.mysqlClient == nil {
		log.Panicln(ErrInvalidMysqlClient)
	}
	return m.mysqlClient
}

func (m *DatabaseManager) MustGetCookieStore() *sessions.CookieStore {
	if m.cookieStore == nil {
		log.Panicln(ErrInvalidCookieStore)
	}
	return m.cookieStore
}
