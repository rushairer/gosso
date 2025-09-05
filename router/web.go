package router

import (
	"gosso/controller"
	"gosso/internal/service"
	"net/http"

	"github.com/rushairer/gouno/task"

	"github.com/gin-gonic/gin"
	gopipeline "github.com/rushairer/go-pipeline"
	"github.com/rushairer/gouno"
	"gorm.io/gorm"
)

func RegisterWebRouter(engine *gin.Engine, db *gorm.DB, taskPipeline *gopipeline.Pipeline[task.Task]) {
	registerWebTestRouter(engine)
	registerWebIndexRouter(engine)
	registerAccountRouter(engine, db, taskPipeline)
}

func registerWebTestRouter(engine *gin.Engine) {
	testGroup := engine.Group("/test")
	{
		testGroup.GET(
			"/alive",
			func(ctx *gin.Context) {
				ctx.JSON(http.StatusOK, gouno.NewSuccessResponse("pong"))
			},
		)
	}
}

func registerWebIndexRouter(engine *gin.Engine) {
	engine.GET("/", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "Hello gouno!")
	})
}

func registerAccountRouter(engine *gin.Engine, db *gorm.DB, taskPipeline *gopipeline.Pipeline[task.Task]) {
	accountGroup := engine.Group("/account")
	{
		accountService := service.NewAccountService(db)
		accountController := controller.NewAccountController(accountService, taskPipeline)

		accountGroup.POST("/email", accountController.EmailRegister)
		accountGroup.POST("/phone", accountController.PhoneRegister)
	}
}
