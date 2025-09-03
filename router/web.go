package router

import (
	"gosso/controller"
	"gosso/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
	"gorm.io/gorm"
)

func RegisterWebRouter(server *gin.Engine, db *gorm.DB) {
	registerWebTestRouter(server)
	registerWebIndexRouter(server)
	registerAccountRouter(server, db)
}

func registerWebTestRouter(server *gin.Engine) {
	testGroup := server.Group("/test")
	{
		testGroup.GET(
			"/alive",
			func(ctx *gin.Context) {
				ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("pong"))
			},
		)
	}
}

func registerWebIndexRouter(server *gin.Engine) {
	server.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "Hello gouno!")
	})
}

func registerAccountRouter(server *gin.Engine, db *gorm.DB) {
	accountGroup := server.Group("/account")
	{
		accountService := service.NewAccountService(db)
		accountController := controller.NewAccountController(accountService)

		accountGroup.POST("/email", accountController.EmailRegister)
		accountGroup.POST("/phone", accountController.PhoneRegister)
	}
}
