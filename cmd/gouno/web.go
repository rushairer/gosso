package gouno

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gosso/config"
	"gosso/middleware"
	"gosso/router"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
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

	viper.BindEnv("gouno_env")
	viper.BindPFlag("gouno_env", cmd.Flags().Lookup("env"))
	env := viper.Get("gouno_env").(string)

	configPath := cmd.Flag("config_path").Value.String()

	viper.BindPFlag("web_server.address", cmd.Flags().Lookup("address"))
	viper.BindPFlag("web_server.port", cmd.Flags().Lookup("port"))
	viper.BindPFlag("web_server.debug", cmd.Flags().Lookup("debug"))

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
	sqlDB, err := sql.Open(config.GlobalConfig.DatabaseConfig.Driver, config.GlobalConfig.DatabaseConfig.DSN)
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}

	dbLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,                                                  // 慢速 SQL 阈值
			LogLevel:                  logger.LogLevel(config.GlobalConfig.DatabaseConfig.LogLevel), // 日志级别
			IgnoreRecordNotFoundError: true,                                                         // 忽略记录器的 ErrRecordNotFound 错误
		},
	)

	gormDB, err := gorm.Open(
		mysql.New(mysql.Config{
			Conn: sqlDB,
		}),
		&gorm.Config{
			Logger: dbLogger,
			NamingStrategy: schema.NamingStrategy{
				SingularTable: true,
			},
		})
	if err != nil {
		log.Fatalf("open database failed, err: %v", err)
	}

	// init gin
	engine := gin.New()
	engine.Use(
		middleware.RecoveryMiddleware(),
		middleware.TimeoutMiddleware(config.GlobalConfig.WebServerConfig.RequestTimeout),
	)
	router.RegisterWebRouter(engine, gormDB)

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
