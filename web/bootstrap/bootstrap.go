package bootstrap

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/core/config"
	"github.com/rushairer/gosso/core/databases"
	"github.com/rushairer/gosso/core/databases/sshtunnel"
	"golang.org/x/crypto/ssh"
)

func SetupServer(server *gin.Engine) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("init services error:", err)
		}
	}()

	log.Println("connecting databases...")

	var sshClient *ssh.Client

	if config.IsDebug {
		log.Println("using ssh client...")
		if newSSHClient, err := sshtunnel.NewSSHClient(
			config.SSHTunnelHost,
			config.SSHTunnelPort,
			config.SSHTunnelUser,
			config.SSHTunnelPassword,
			config.SSHTunnelPrivateKey,
		); newSSHClient != nil && err == nil {
			log.Println("ssh client is OK")
			sshClient = newSSHClient
		}
	}

	databaseManager := databases.NewDatabaseManager(
		config.MysqlDSN,
		config.SessionSecret,
		sshClient,
	)

	if mysqlClient := databaseManager.GetMysqlClient(); mysqlClient != nil {
		log.Println("mysql is OK")
	}
	if cookieStore := databaseManager.GetCookieStore(); cookieStore != nil {
		log.Println("session is OK")
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
