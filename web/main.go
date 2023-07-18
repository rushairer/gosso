package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/core/config"
	"github.com/rushairer/gosso/web/bootstrap"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Println("gosso/web crashed, error:", err)
		}
	}()

	log.Println("starting...")
	server := gin.Default()
	bootstrap.SetupServer(server)

	log.Println("running...")
	if gin.IsDebugging() {
		if err := server.RunTLS(
			":443",
			"./web/resources/dev.apigg.net.crt",
			"./web/resources/dev.apigg.net.key",
		); err != nil {
			log.Println(err)
		}
	} else {
		if err := server.Run(fmt.Sprintf(":%s", config.ServerPort)); err != nil {
			log.Println(err)
		}
	}
}
