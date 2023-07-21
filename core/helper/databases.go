package helper

import (
	"log"

	"github.com/rushairer/gosso/core/config"
	"github.com/rushairer/gosso/core/databases"
	"github.com/rushairer/gosso/core/utilities/sshtunnel"
	"golang.org/x/crypto/ssh"
)

func NewDatabaseManagerDefault() *databases.DatabaseManager {
	var sshClient *ssh.Client

	if config.IsDebug {
		log.Println("[NewDatabaseManagerDefault]", "starting ssh client...")
		if newSSHClient, err := sshtunnel.NewSSHClient(
			config.SSHTunnelHost,
			config.SSHTunnelPort,
			config.SSHTunnelUser,
			config.SSHTunnelPassword,
			config.SSHTunnelPrivateKey,
		); newSSHClient != nil && err == nil {
			log.Println("[NewDatabaseManagerDefault]", "ssh client is ready")
			sshClient = newSSHClient
		}
	}

	return databases.NewDatabaseManager(
		config.MysqlDSN,
		config.SessionName,
		config.SessionSecret,
		sshClient,
	)
}
