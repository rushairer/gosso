package config

import (
	"log"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

type ConfigManager struct {
	configMutex sync.RWMutex
	config      *GoUnoConfig
}

func NewConfigManager(
	configPath string,
	env string,
) *ConfigManager {

	configManager := ConfigManager{}

	configManager.setConfigDefaults()
	viper.AddConfigPath(configPath)
	viper.SetConfigName(env)
	viper.SetConfigType("yaml")

	viper.SetEnvPrefix("GOUNO")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("read config failed, err: %v", err)
		return nil
	}

	newConifg := GoUnoConfig{}
	if err := viper.Unmarshal(&newConifg); err != nil {
		log.Fatalf("unmarshal config failed, err: %v", err)
		return nil
	}
	configManager.SetConfig(&newConifg)
	return &configManager
}

func (cm *ConfigManager) SetConfig(config *GoUnoConfig) {
	cm.configMutex.Lock()
	defer cm.configMutex.Unlock()
	cm.config = config
}

func (cm *ConfigManager) Config() GoUnoConfig {
	cm.configMutex.RLock()
	defer cm.configMutex.RUnlock()
	return *cm.config
}

func (cm *ConfigManager) setConfigDefaults() {
	// 验证码配置
	viper.SetDefault("captcha_type", "math")

	// Web服务器配置
	viper.SetDefault("web_server.debug", false)
	viper.SetDefault("web_server.address", "0.0.0.0")
	viper.SetDefault("web_server.port", "8080")
	viper.SetDefault("web_server.idle_timeout", "60s")
	viper.SetDefault("web_server.read_timeout", "5s")
	viper.SetDefault("web_server.read_header_timeout", "2s")
	viper.SetDefault("web_server.write_timeout", "30s")
	viper.SetDefault("web_server.request_timeout", "10s")
	viper.SetDefault("web_server.rate_limit_per_minute", 100)

	// 数据库配置
	viper.SetDefault("database.default", "sqlite")
	viper.SetDefault("database.drivers.sqlite.name", "sqlite")
	viper.SetDefault("database.drivers.sqlite.driver", "sqlite3")
	viper.SetDefault("database.drivers.sqlite.dsn", ":memory:")
	viper.SetDefault("database.drivers.sqlite.log_level", 1)
}
