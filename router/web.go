package router

import (
	"gosso/config"
	"gosso/controller"
	"gosso/internal/service/account"
	"gosso/middleware"
	"net/http"
	"time"

	"github.com/rushairer/gouno/task"

	"github.com/gin-gonic/gin"
	gopipeline "github.com/rushairer/go-pipeline"
	"github.com/rushairer/gouno"
	gounoMiddleware "github.com/rushairer/gouno/middleware"
	"gorm.io/gorm"
)

func RegisterWebRouter(config config.GoUnoConfig, engine *gin.Engine, db *gorm.DB, taskPipeline *gopipeline.Pipeline[task.Task]) {
	registerWebTestRouter(engine)
	registerWebIndexRouter(engine)
	registerAccountRouter(engine, db, taskPipeline)
	registerCaptchaRouter(config, engine)
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

		testGroup.POST(
			"/verify_captcha",
			middleware.RequireCaptchaMiddleware(),
			func(ctx *gin.Context) {
				var req interface{}

				if err := ctx.ShouldBindJSON(&req); err == nil {
					ctx.JSON(http.StatusOK, gouno.NewSuccessResponse(req))
				} else {
					ctx.JSON(http.StatusOK, gouno.NewErrorResponse(http.StatusBadRequest, err.Error()))
				}
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
		accountService := account.NewAccountService(db)
		accountController := controller.NewAccountController(accountService, taskPipeline)

		accountGroup.POST("/email", accountController.EmailRegister)
		accountGroup.POST("/phone", accountController.PhoneRegister)
	}
}

func registerCaptchaRouter(config config.GoUnoConfig, engine *gin.Engine) {
	captchaGroup := engine.Group("/captcha")
	captchaGroup.Use(gounoMiddleware.RateLimitMiddleware(20, time.Minute*5))
	{
		captchaController := controller.NewCaptchaController(config.CaptchaType)
		captchaGroup.GET("/generate", captchaController.Generate)
	}
}
