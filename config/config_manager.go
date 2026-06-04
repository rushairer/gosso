package config

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ConfigManager struct {
	configMutex sync.RWMutex
	config      *GoUnoConfig
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
		if f := cmd.Flags().Lookup("address"); f != nil {
			_ = v.BindPFlag("web_server.address", f)
		}
		if f := cmd.Flags().Lookup("port"); f != nil {
			_ = v.BindPFlag("web_server.port", f)
		}
		if f := cmd.Flags().Lookup("debug"); f != nil {
			_ = v.BindPFlag("web_server.debug", f)
		}
		if f := cmd.Flags().Lookup("env"); f != nil {
			_ = v.BindPFlag("gouno_env", f)
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
	cm.configMutex.Lock()
	defer cm.configMutex.Unlock()
	cm.config = config
}

func (cm *ConfigManager) Config() GoUnoConfig {
	cm.configMutex.RLock()
	defer cm.configMutex.RUnlock()
	if cm.config == nil {
		return GoUnoConfig{}
	}
	return *cm.config
}

func (cm *ConfigManager) setConfigDefaults(v *viper.Viper) {
	// Captcha configuration
	v.SetDefault("captcha.type", "math")

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
	v.SetDefault("database.default", "sqlite")
	v.SetDefault("database.drivers.sqlite.name", "sqlite")
	v.SetDefault("database.drivers.sqlite.driver", "sqlite3")
	v.SetDefault("database.drivers.sqlite.dsn", ":memory:")
	v.SetDefault("database.drivers.sqlite.log_level", 1)

	// Auth configuration
	v.SetDefault("auth.access_token_expiry", "15m")
	v.SetDefault("auth.refresh_token_expiry", "168h")
	v.SetDefault("auth.session_ttl", "24h")
	v.SetDefault("auth.issuer", "gosso")
	v.SetDefault("auth.authorization_code_expiry", "5m")
	v.SetDefault("auth.device_code_expiry", "10m")
	v.SetDefault("auth.device_code_interval", "5s")
	v.SetDefault("auth.id_token_expiry", "15m")

	// Log configuration
	v.SetDefault("log.level", 0)
}
