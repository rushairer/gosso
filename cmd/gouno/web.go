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
	"github.com/rushairer/gosso/utility"
	gounoMiddleware "github.com/rushairer/gouno/middleware"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configPath := cmd.Flag("config_path").Value.String()
	env := cmd.Flag("env").Value.String()

	configManager := config.NewConfigManager(cmd, configPath, env)
	globalConfig := configManager.Config()

	if globalConfig.WebServerConfig.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	loggerLevel := zap.NewAtomicLevelAt(zapcore.Level(globalConfig.LogConfig.Level))
	logger := utility.NewLogger(loggerLevel)

	logger.Sugar().Info("starting web server...")

	// init db
	// defaultDriver := globalConfig.DatabaseConfig.GetDefaultDriver()
	// if defaultDriver == nil {
	// 	log.Fatalf("default driver not found")
	// }

	engine := gin.New()
	engine.Use(
		gin.Logger(),
		middleware.RecoveryMiddleware(),
		middleware.TimeoutMiddleware(globalConfig.WebServerConfig.RequestTimeout),
		gounoMiddleware.RateLimitMiddleware(ctx, globalConfig.WebServerConfig.RateLimitPerMinute, time.Minute),
	)
	router.RegisterWebRouter(engine)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", globalConfig.WebServerConfig.Address, globalConfig.WebServerConfig.Port),
		IdleTimeout:       globalConfig.WebServerConfig.IdleTimeout,
		WriteTimeout:      globalConfig.WebServerConfig.WriteTimeout,
		ReadTimeout:       globalConfig.WebServerConfig.ReadTimeout,
		ReadHeaderTimeout: globalConfig.WebServerConfig.ReadHeaderTimeout,
		Handler:           engine,
	}

	logger.Sugar().Infof("web server listening on %s", httpServer.Addr)
	logger.Sugar().Info("press Ctrl+C to exit")

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	logger.Sugar().Info("shutting down gracefully, press Ctrl+C again to force")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	// Close

	logger.Sugar().Info("server exiting")
}
