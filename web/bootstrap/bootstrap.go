package bootstrap

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/core/config"
	"github.com/rushairer/gosso/core/databases"
	"github.com/rushairer/gosso/core/utilities/sshtunnel"
	"golang.org/x/crypto/ssh"
)

func SetupServer(server *gin.Engine) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("[bootstrap]", "init services error:", err)
		}
	}()

	log.Println("[bootstrap]", "connecting databases...")

	var sshClient *ssh.Client

	if config.IsDebug {
		log.Println("[bootstrap]", "starting ssh client...")
		if newSSHClient, err := sshtunnel.NewSSHClient(
			config.SSHTunnelHost,
			config.SSHTunnelPort,
			config.SSHTunnelUser,
			config.SSHTunnelPassword,
			config.SSHTunnelPrivateKey,
		); newSSHClient != nil && err == nil {
			log.Println("[bootstrap]", "ssh client is ready")
			sshClient = newSSHClient
		}
	}

	databaseManager := databases.NewDatabaseManager(
		config.MysqlDSN,
		config.SessionSecret,
		sshClient,
	)

	if mysqlClient := databaseManager.MustGetMysqlClient(); mysqlClient != nil {
		log.Println("[bootstrap]", "mysql is ready")
	}
	if cookieStore := databaseManager.MustGetCookieStore(); cookieStore != nil {
		log.Println("[bootstrap]", "session is ready")
	}

	testGroup := server.Group("/test")
	{
		testGroup.GET(
			"/alive",
			func(ctx *gin.Context) {
				ctx.String(http.StatusOK, "pong")
			},
		)
	}
}
