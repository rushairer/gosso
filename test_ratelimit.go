package main

import (
	"fmt"
	"net/http"
	"time"

	"gosso/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	// 使用我们的限频中间件：每分钟2次（用于测试）
	r.Use(middleware.RateLimitMiddleware(2, time.Minute))

	r.GET("/test/alive", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"code":    0,
			"message": "success",
			"data":    "pong",
		})
	})

	fmt.Println("测试服务器启动在 :8082")
	fmt.Println("测试命令:")
	fmt.Println("curl -v localhost:8082/test/alive")

	http.ListenAndServe(":8082", r)
}
