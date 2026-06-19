package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// defaultPostgresDSN is the default development DSN.
// Validate() rejects this value to prevent production from accidentally using dev credentials.
const defaultPostgresDSN = "postgres://postgres:postgres@localhost:5432/gosso?sslmode=disable"

// defaultTOTPEncryptionKey is the default development TOTP encryption key.
// Validate() rejects this value to prevent production from using a publicly known key.
const defaultTOTPEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// ConfigManager loads, validates, and exposes the application configuration.
// Immutable after construction — safe for concurrent reads.
type ConfigManager struct {
	config GoUnoConfig // immutable after construction; returned by value (Go struct copy)
}

// NewConfigManager creates a configuration manager.
// cmd is an optional Cobra command for binding CLI flags to config keys; may be nil.
func NewConfigManager(
	cmd *cobra.Command,
	configPath string,
	env string,
) (*ConfigManager, error) {

	configManager := ConfigManager{}

	v := viper.New()
	configManager.setConfigDefaults(v)
	v.AddConfigPath(configPath)
	v.SetConfigName(env)
	v.SetConfigType("yaml")

	v.SetEnvPrefix("GOUNO")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Bind CLI flags to the local viper instance
	if cmd != nil {
		flagBindings := map[string]string{
			"address": "web_server.address",
			"port":    "web_server.port",
			"debug":   "web_server.debug",
			"env":     "gouno_env",
		}
		for flagName, viperKey := range flagBindings {
			if f := cmd.Flags().Lookup(flagName); f != nil {
				if err := v.BindPFlag(viperKey, f); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to bind flag '%s': %v\n", flagName, err)
				}
			}
		}
	}

	if err := v.ReadInConfig(); err != nil {
		// Allow missing config file — all settings can come from environment variables
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("read config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Warning: config file not found at %s, using defaults and environment variables\n", configPath)
	}

	newConfig := GoUnoConfig{}
	if err := v.Unmarshal(&newConfig); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := newConfig.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	configManager.config = newConfig
	return &configManager, nil
}

// Config returns a copy of the configuration.
// Since the config is immutable after construction, a simple struct copy
// (Go value assignment) is safe and much cheaper than JSON round-tripping.
func (cm *ConfigManager) Config() GoUnoConfig {
	return cm.config
}

func (cm *ConfigManager) setConfigDefaults(v *viper.Viper) {
	// Web server configuration
	v.SetDefault("web_server.debug", false)
	v.SetDefault("web_server.address", "0.0.0.0")
	v.SetDefault("web_server.port", "8080")
	v.SetDefault("web_server.idle_timeout", "60s")
	v.SetDefault("web_server.read_timeout", "5s")
	v.SetDefault("web_server.read_header_timeout", "2s")
	v.SetDefault("web_server.write_timeout", "30s")
	v.SetDefault("web_server.request_timeout", "10s")
	v.SetDefault("web_server.shutdown_timeout", "30s")
	v.SetDefault("web_server.max_body_size", 10*1024*1024) // 10MB
	v.SetDefault("web_server.rate_limits.login", 5)
	v.SetDefault("web_server.rate_limits.token", 10)
	v.SetDefault("web_server.rate_limits.passkey", 10)
	v.SetDefault("web_server.rate_limits.api", 60)
	v.SetDefault("web_server.rate_limits.introspect", 20)
	v.SetDefault("web_server.rate_limits.device_code", 10)
	v.SetDefault("web_server.rate_limits.password", 3)
	v.SetDefault("web_server.rate_limits.verify", 3)
	v.SetDefault("web_server.rate_limits.admin", 30)

	// Database configuration
	v.SetDefault("database.default", "postgres")
	v.SetDefault("database.drivers.postgres.name", "postgres")
	v.SetDefault("database.drivers.postgres.driver", "pgx")
	v.SetDefault("database.drivers.postgres.dsn", defaultPostgresDSN)
	v.SetDefault("database.drivers.postgres.log_level", 1)
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 15)
	v.SetDefault("database.conn_max_lifetime_sec", 300)  // 5 minutes
	v.SetDefault("database.conn_max_idle_time_sec", 180) // 3 minutes
	v.SetDefault("database.pool_stats_interval_sec", 60) // 1 minute; 0 disables

	// Auth configuration
	v.SetDefault("auth.access_token_expiry", "15m")
	v.SetDefault("auth.refresh_token_expiry", "168h")
	v.SetDefault("auth.session_ttl", "24h")
	v.SetDefault("auth.issuer", "http://localhost:8080")
	v.SetDefault("auth.authorization_code_expiry", "5m")
	v.SetDefault("auth.device_code_expiry", "10m")
	v.SetDefault("auth.device_code_interval", "5s")
	v.SetDefault("auth.id_token_expiry", "15m")
	v.SetDefault("auth.max_sessions", 5)
	v.SetDefault("auth.totp_encryption_key", defaultTOTPEncryptionKey)

	// Redis configuration
	v.SetDefault("redis.max_active_conns", 10)
	v.SetDefault("redis.pool_timeout_seconds", 5)

	// Log configuration
	v.SetDefault("log.level", 0)
	v.SetDefault("log.format", "console")
}
