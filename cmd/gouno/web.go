package gouno

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/rushairer/gosso/config"
	auditService "github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/utility"
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

	configManager, err := config.NewConfigManager(cmd, configPath, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1) //nolint:gocritic // stop() is best-effort signal cleanup, safe to skip on fatal init error
	}
	globalConfig := configManager.Config()

	if globalConfig.WebServerConfig.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	loggerLevel := zap.NewAtomicLevelAt(zapcore.Level(globalConfig.LogConfig.Level))
	logger := utility.NewLogger(loggerLevel, globalConfig.LogConfig.Format)

	if err := globalConfig.Validate(); err != nil {
		logger.Error("invalid configuration", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("starting web server",
		zap.String("env", env),
		zap.Bool("debug", globalConfig.WebServerConfig.Debug),
		zap.String("addr", globalConfig.WebServerConfig.Address+":"+globalConfig.WebServerConfig.Port),
	)

	db, err := initDatabase(globalConfig, logger)
	if err != nil {
		logger.Error("database init failed", zap.Error(err))
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	redis, err := initRedis(globalConfig, logger)
	if err != nil {
		logger.Error("redis init failed", zap.Error(err))
		os.Exit(1)
	}
	defer func() { _ = redis.Close() }()

	auditAuditor := auditService.NewAuditor(ctx, db, &globalConfig.TaskPipelineConfig, logger)
	go listenAuditErrors(ctx, auditAuditor, logger)

	modules, err := initModules(ctx, db, redis, logger, globalConfig, auditAuditor)
	if err != nil {
		logger.Error("module initialization failed", zap.Error(err))
		os.Exit(1)
	}

	engine, err := setupEngine(ctx, globalConfig, logger, modules, db, redis)
	if err != nil {
		logger.Error("engine setup failed", zap.Error(err))
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", globalConfig.WebServerConfig.Address, globalConfig.WebServerConfig.Port),
		IdleTimeout:       globalConfig.WebServerConfig.IdleTimeout,
		WriteTimeout:      globalConfig.WebServerConfig.WriteTimeout,
		ReadTimeout:       globalConfig.WebServerConfig.ReadTimeout,
		ReadHeaderTimeout: globalConfig.WebServerConfig.ReadHeaderTimeout,
		Handler:           engine,
	}

	logger.Info("web server listening", zap.String("addr", httpServer.Addr))
	logger.Info("press Ctrl+C to exit")

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("listen failed", zap.Error(err))
			stop()
		}
	}()

	<-ctx.Done()

	stop()
	logger.Info("shutting down gracefully, waiting for active requests to finish",
		zap.Duration("timeout", globalConfig.WebServerConfig.ShutdownTimeout))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), globalConfig.WebServerConfig.ShutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("server forced to shutdown", zap.Error(err))
	}

	// Wait for background goroutines (e.g., session revocation after password reset) to complete
	if modules.passwordResetSvc != nil {
		modules.passwordResetSvc.Wait()
	}

	// Drain in-flight audit batches before exiting
	auditAuditor.Wait()

	_ = logger.Sync()
	logger.Info("server exiting")
}
