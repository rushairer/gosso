package gouno

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/internal/audit/service"
	"github.com/rushairer/gosso/internal/cache"
)

// initDatabase initializes the database connection
func initDatabase(ctx context.Context, cfg config.GoUnoConfig, logger *zap.Logger) (*sql.DB, error) {
	defaultDriver := cfg.DatabaseConfig.GetDefaultDriver()
	if defaultDriver == nil {
		return nil, fmt.Errorf("default database driver not found")
	}

	db, err := sql.Open(defaultDriver.Driver, defaultDriver.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(cfg.DatabaseConfig.MaxOpenConns)
	db.SetMaxIdleConns(cfg.DatabaseConfig.MaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(cfg.DatabaseConfig.ConnMaxLifetimeSec) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(cfg.DatabaseConfig.ConnMaxIdleTimeSec) * time.Second)

	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info("database connected")

	// Start background goroutine to periodically log connection pool stats.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				stats := db.Stats()
				logger.Info("db pool stats",
					zap.Int("open", stats.OpenConnections),
					zap.Int("in_use", stats.InUse),
					zap.Int("idle", stats.Idle),
					zap.Int64("wait_count", stats.WaitCount),
					zap.Duration("wait_duration", stats.WaitDuration),
					zap.Int64("max_idle_closed", stats.MaxIdleClosed),
					zap.Int64("max_lifetime_closed", stats.MaxLifetimeClosed),
				)
			case <-ctx.Done():
				return
			}
		}
	}()

	return db, nil
}

// initRedis initializes the Redis connection
func initRedis(cfg config.GoUnoConfig, logger *zap.Logger) (*cache.RedisClient, error) {
	redis, err := cache.NewRedisClient(
		cfg.RedisConfig.DSN,
		cfg.RedisConfig.MaxActiveConns,
		time.Duration(cfg.RedisConfig.PoolTimeoutSeconds)*time.Second,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	logger.Info("redis connected")
	return redis, nil
}

// listenAuditErrors listens for audit errors and logs them
func listenAuditErrors(ctx context.Context, auditor *service.Auditor, logger *zap.Logger) {
	for {
		select {
		case err, ok := <-auditor.ErrorChan():
			if !ok {
				return
			}
			logger.Error("Audit batch error", zap.Error(err))
		case <-ctx.Done():
			// Drain remaining buffered errors before exiting
			for {
				select {
				case err, ok := <-auditor.ErrorChan():
					if !ok {
						return
					}
					logger.Error("Audit batch error (draining)", zap.Error(err))
				default:
					return
				}
			}
		}
	}
}
