package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// defaultPostgresDSN is the default development DSN.
// Validate() rejects this value to prevent production from accidentally using dev credentials.
const defaultPostgresDSN = "postgres://postgres:postgres@localhost:5432/gosso?sslmode=disable"

// ConfigManager loads, validates, and exposes the application configuration.
type ConfigManager struct {
	config *GoUnoConfig
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
		return nil, fmt.Errorf("read config: %w", err)
	}

	newConfig := GoUnoConfig{}
	if err := v.Unmarshal(&newConfig); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	configManager.SetConfig(&newConfig)
	return &configManager, nil
}

func (cm *ConfigManager) SetConfig(config *GoUnoConfig) {
	cm.config = config
}

func (cm *ConfigManager) Config() GoUnoConfig {
	if cm.config == nil {
		return GoUnoConfig{}
	}
	return *cm.config
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
	v.SetDefault("web_server.max_body_size", 10*1024*1024) // 10MB
	v.SetDefault("web_server.rate_limits.login", 5)
	v.SetDefault("web_server.rate_limits.token", 10)
	v.SetDefault("web_server.rate_limits.passkey", 10)
	v.SetDefault("web_server.rate_limits.api", 60)
	v.SetDefault("web_server.rate_limits.introspect", 20)
	v.SetDefault("web_server.rate_limits.device_code", 10)

	// Database configuration
	v.SetDefault("database.default", "postgres")
	v.SetDefault("database.drivers.postgres.name", "postgres")
	v.SetDefault("database.drivers.postgres.driver", "pgx")
	v.SetDefault("database.drivers.postgres.dsn", defaultPostgresDSN)
	v.SetDefault("database.drivers.postgres.log_level", 1)
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime_sec", 300)  // 5 minutes
	v.SetDefault("database.conn_max_idle_time_sec", 180) // 3 minutes

	// Auth configuration
	v.SetDefault("auth.access_token_expiry", "15m")
	v.SetDefault("auth.refresh_token_expiry", "168h")
	v.SetDefault("auth.session_ttl", "24h")
	v.SetDefault("auth.issuer", "gosso")
	v.SetDefault("auth.authorization_code_expiry", "5m")
	v.SetDefault("auth.device_code_expiry", "10m")
	v.SetDefault("auth.device_code_interval", "5s")
	v.SetDefault("auth.id_token_expiry", "15m")

	// Redis configuration
	v.SetDefault("redis.max_active_conns", 10)
	v.SetDefault("redis.pool_timeout_seconds", 5)

	// Log configuration
	v.SetDefault("log.level", 0)
	v.SetDefault("log.format", "console")
}
