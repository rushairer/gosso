package bootstrap

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/core/authentication"
	"github.com/rushairer/gosso/core/config"
	"github.com/rushairer/gosso/core/databases"
	"github.com/rushairer/gosso/core/socialite"
	"github.com/rushairer/gosso/core/utilities/sshtunnel"
	"github.com/rushairer/gosso/web/controllers"
	"github.com/rushairer/gosso/web/middlewares"
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
		} else {
			log.Println("[bootstrap]", err)
		}
	}

	databaseManager := databases.NewDatabaseManager(
		config.MysqlDSN,
		config.SessionName,
		config.SessionSecret,
		sshClient,
	)

	mysqlClient := databaseManager.MustGetMysqlClient()
	if mysqlClient != nil {
		log.Println("[bootstrap]", "mysql is ready")
	}

	sessionStore := databaseManager.MustGetSessionStore()

	testGroup := server.Group("/test")
	{
		testGroup.GET(
			"/alive",
			func(ctx *gin.Context) {
				ctx.String(http.StatusOK, "pong")
			},
		)
	}

	authenticationService := authentication.NewAuthenticationService(mysqlClient, sessionStore)
	socialiteService := socialite.NewSocialiteService(mysqlClient)
	socialiteMiddleware := middlewares.NewSocialiteMiddleware()
	socialiteController := controllers.NewSocialsController(
		config.HomePagePath,
		config.SignInPagePath,
		socialiteService,
		authenticationService,
	)
	socialsGroup := server.Group("/socials")
	{
		socialsGroup.GET(
			"/:provider",
			socialiteMiddleware.GetProviderName,
			socialiteController.SignIn,
		)

		socialsGroup.GET(
			"/:provider/callback",
			socialiteMiddleware.GetProviderName,
			socialiteController.Callback,
		)
	}

}
