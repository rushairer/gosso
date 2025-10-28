package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gouno"
)

func RegisterWebRouter(server *gin.Engine) {
	registerWebTestRouter(server)
	registerWebIndexRouter(server)
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
