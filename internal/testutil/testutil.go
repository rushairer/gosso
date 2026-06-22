package testutil

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/rushairer/gosso/config"
	accountDomain "github.com/rushairer/gosso/internal/account/domain"
	"github.com/rushairer/gosso/internal/cache"
)

// SetupTestRedis starts a miniredis instance and returns a RedisClient connected to it.
// The caller must defer mr.Close() to clean up the miniredis server.
func SetupTestRedis(t *testing.T) (*cache.RedisClient, *miniredis.Miniredis) {
	t.Helper()
	RequireLocalTCPListen(t, "tcp4", "127.0.0.1:0")
	logger := zap.NewNop()

	mr := miniredis.RunT(t)

	redisClient, err := cache.NewRedisClient(context.Background(), "redis://"+mr.Addr(), 10, 5*time.Second, 5*time.Second, 3*time.Second, 3*time.Second, logger)
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create test redis client: %v", err)
	}

	return redisClient, mr
}

// RequireLocalTCPListen skips the test when the current execution environment
// forbids local TCP listeners. This keeps tests runnable in restricted
// sandboxes while preserving full coverage on normal developer machines and CI.
func RequireLocalTCPListen(t *testing.T, network, address string) {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Skipf("skipping: local TCP listen unavailable (%s %s): %v", network, address, err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close local TCP probe listener: %v", err)
	}
}

// RequireLocalHTTPServer skips tests that use httptest.NewServer. Go's
// httptest package opens a loopback listener, often on IPv6 first.
func RequireLocalHTTPServer(t *testing.T) {
	t.Helper()
	RequireLocalTCPListen(t, "tcp6", "[::1]:0")
}

// SkipIfNoCJSON probes whether the Redis instance supports the Lua cjson module.
// Miniredis does not support cjson, so tests that rely on cjson-based Lua scripts
// are skipped when running against miniredis.
func SkipIfNoCJSON(t *testing.T, rds *cache.RedisClient) {
	t.Helper()
	probe := redis.NewScript(`local cjson = require('cjson'); return cjson.encode({ok=true})`)
	if err := probe.Run(context.Background(), rds.GetClient(), nil).Err(); err != nil {
		t.Skip("Skipping: Redis does not support cjson Lua module (miniredis)")
	}
}

// TestEnv holds shared test infrastructure connections.
type TestEnv struct {
	DB       *sql.DB
	Redis    *cache.RedisClient
	Config   config.GoUnoConfig
	Logger   *zap.Logger
	cleanups []func()
}

// SetupTestEnv loads test config, connects to Postgres + Redis, runs migrations.
// Requires docker-compose.test.yml to be running (make docker-test-up).
func SetupTestEnv(ctx context.Context) (*TestEnv, error) {
	// Resolve config path relative to project root
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	configPath := filepath.Join(projectRoot, "config")

	cm, err := config.NewConfigManager(nil, configPath, "test")
	if err != nil {
		return nil, fmt.Errorf("load test config: %w", err)
	}
	cfg := cm.Config()

	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	// Connect to Postgres
	dbDriver := cfg.DatabaseConfig.GetDefaultDriver()
	if dbDriver == nil {
		return nil, fmt.Errorf("default database driver not found in test config")
	}

	db, err := sql.Open("pgx", dbDriver.DSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if pingErr := db.PingContext(ctx); pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w (is docker-compose.test.yml running?)", pingErr)
	}

	// Run migrations
	migrationsPath := filepath.Join(projectRoot, "db", "migrations")
	if migrateErr := runMigrations(db, migrationsPath); migrateErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("run migrations: %w", migrateErr)
	}

	// Connect to Redis
	redis, err := cache.NewRedisClient(context.Background(), cfg.RedisConfig.DSN, 10, 10*time.Second, 5*time.Second, 3*time.Second, 3*time.Second, logger)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect redis: %w (is docker-compose.test.yml running?)", err)
	}

	env := &TestEnv{
		DB:     db,
		Redis:  redis,
		Config: cfg,
		Logger: logger,
	}
	env.cleanups = append(env.cleanups,
		func() { _ = db.Close() },
		func() { _ = redis.Close() },
	)

	return env, nil
}

// Cleanup closes all connections.
func (e *TestEnv) Cleanup() {
	for i := len(e.cleanups) - 1; i >= 0; i-- {
		e.cleanups[i]()
	}
}

// SetupTestEnvT is like SetupTestEnv but automatically registers cleanup with t.Cleanup().
func SetupTestEnvT(t *testing.T) *TestEnv {
	t.Helper()
	env, err := SetupTestEnv(context.Background())
	if err != nil {
		t.Fatalf("setup test env: %v", err)
	}
	t.Cleanup(env.Cleanup)
	return env
}

// TruncateAll truncates all test data between tests.
func (e *TestEnv) TruncateAll(ctx context.Context) error {
	tables := []string{
		"account_roles",
		"roles",
		"federated_identities",
		"account_credentials",
		"accounts",
		"oauth2_clients",
		"oauth2_consents",
		"webauthn_credentials",
		"audit_record",
		"audit_entry",
	}
	for _, t := range tables {
		if _, err := e.DB.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", t)); err != nil {
			// Ignore missing tables (some migrations may not have run).
			// Genuine failures (permission, lock contention) are logged but not returned
			// because test teardown should not fail the test — stale data is a softer
			// problem than a flaky test suite.
			e.Logger.Debug("truncate table failed (may not exist)", zap.String("table", t), zap.Error(err))
		}
	}

	// Flush test Redis keys
	rdb := e.Redis.GetClient()
	if rdb != nil {
		if err := rdb.FlushDB(ctx).Err(); err != nil {
			e.Logger.Warn("flush redis failed", zap.Error(err))
			return fmt.Errorf("flush test redis: %w", err)
		}
	}

	return nil
}

// SeedAccount inserts a test account with a password credential.
// Returns account ID.
func (e *TestEnv) SeedAccount(ctx context.Context, username, email, password string) (string, error) {
	var accountID string
	err := e.DB.QueryRowContext(ctx,
		`INSERT INTO accounts (username, display_name, status) VALUES ($1, $1, 'active') RETURNING id`,
		username,
	).Scan(&accountID)
	if err != nil {
		return "", fmt.Errorf("insert account: %w", err)
	}

	// Insert password credential (argon2id hash)
	hash, err := accountDomain.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	_, err = e.DB.ExecContext(ctx,
		`INSERT INTO account_credentials (account_id, credential_type, identifier, credential_value, verified, primary_credential)
		 VALUES ($1, 'password', $2, $3, true, true)`,
		accountID, username, hash,
	)
	if err != nil {
		return "", fmt.Errorf("insert credential: %w", err)
	}

	// Insert email credential
	if email != "" {
		_, err = e.DB.ExecContext(ctx,
			`INSERT INTO account_credentials (account_id, credential_type, identifier, verified, primary_credential)
			 VALUES ($1, 'email', $2, true, false)`,
			accountID, email,
		)
		if err != nil {
			return "", fmt.Errorf("insert email credential: %w", err)
		}
	}

	return accountID, nil
}

func runMigrations(db *sql.DB, migrationsPath string) error {
	absPath, err := filepath.Abs(migrationsPath)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{
		MigrationsTable: "schema_migrations",
	})
	if err != nil {
		return fmt.Errorf("create postgres driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", absPath),
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("create migrate instance: %w", err)
	}
	// Don't defer m.Close() — the golang-migrate postgres driver closes
	// the underlying *sql.DB on Close(), which kills the shared connection.

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}

	return nil
}
