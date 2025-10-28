package gouno

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/middleware"
	"github.com/rushairer/gosso/router"
	gounoMiddleware "github.com/rushairer/gouno/middleware"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var webCmd = &cobra.Command{
	Use: "web",
	Run: startWebServer,
}

func init() {
	webCmd.Flags().StringP("config_path", "c", "./config", "config file path")
	webCmd.Flags().StringP("address", "a", "0.0.0.0", "address to listen on")
	webCmd.Flags().StringP("port", "p", "8080", "port to listen on")
	webCmd.Flags().BoolP("debug", "d", false, "debug mode")
	webCmd.Flags().StringP("env", "e", "production", "env: development, test, production")
}

func startWebServer(cmd *cobra.Command, args []string) {
	log.Printf("starting web server...")

	if err := viper.BindEnv("gouno_env"); err != nil {
		log.Fatalf("bind env failed, err: %v", err)
	}
	if err := viper.BindPFlag("gouno_env", cmd.Flags().Lookup("env")); err != nil {
		log.Fatalf("bind flag failed, err: %v", err)
	}
	env := viper.Get("gouno_env").(string)

	configPath := cmd.Flag("config_path").Value.String()

	if err := viper.BindPFlag("web_server.address", cmd.Flags().Lookup("address")); err != nil {
		log.Fatalf("bind address flag failed, err: %v", err)
	}
	if err := viper.BindPFlag("web_server.port", cmd.Flags().Lookup("port")); err != nil {
		log.Fatalf("bind port flag failed, err: %v", err)
	}
	if err := viper.BindPFlag("web_server.debug", cmd.Flags().Lookup("debug")); err != nil {
		log.Fatalf("bind debug flag failed, err: %v", err)
	}

	err := config.InitConfig(configPath, env)
	if err != nil {
		log.Fatalf("init config failed, err: %v", err)
	}

	if config.GlobalConfig.WebServerConfig.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create context that listens for the interrupt signal from the OS.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// init db
	// defaultDriver := config.GlobalConfig.DatabaseConfig.GetDefaultDriver()
	// if defaultDriver == nil {
	// 	log.Fatalf("default driver not found")
	// }

	engine := gin.New()
	engine.Use(
		gin.Logger(),
		middleware.RecoveryMiddleware(),
		middleware.TimeoutMiddleware(config.GlobalConfig.WebServerConfig.RequestTimeout),
		gounoMiddleware.RateLimitMiddleware(config.GlobalConfig.WebServerConfig.RateLimitPerMinute, time.Minute),
	)
	router.RegisterWebRouter(engine)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", config.GlobalConfig.WebServerConfig.Address, config.GlobalConfig.WebServerConfig.Port),
		IdleTimeout:       config.GlobalConfig.WebServerConfig.IdleTimeout,
		WriteTimeout:      config.GlobalConfig.WebServerConfig.WriteTimeout,
		ReadTimeout:       config.GlobalConfig.WebServerConfig.ReadTimeout,
		ReadHeaderTimeout: config.GlobalConfig.WebServerConfig.ReadHeaderTimeout,
		Handler:           engine,
	}

	log.Printf("listening on %s", httpServer.Addr)
	log.Printf("press Ctrl+C to exit")

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	log.Printf("shutting down gracefully, press Ctrl+C again to force")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	// Close

	log.Printf("server exiting")
}
