package databases

import (
	"database/sql"
	"log"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/rushairer/gosso/core/databases/sshtunnel"
	"golang.org/x/crypto/ssh"
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

func (m *DatabaseManager) GetMysqlClient() *sql.DB {
	return m.mysqlClient
}

func (m *DatabaseManager) GetCookieStore() *sessions.CookieStore {
	return m.cookieStore
}
