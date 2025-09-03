package config

import (
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var GlobalConfig GoUnoConfig

type GoUnoConfig struct {
	WebServerConfig WebServerConfig `mapstructure:"web_server"`
	DatabaseConfig  DatabaseConfig  `mapstructure:"database"`
}

type WebServerConfig struct {
	Debug             bool          `mapstructure:"debug"`
	Address           string        `mapstructure:"address"`
	Port              string        `mapstructure:"port"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	ReadTimeout       time.Duration `mapstructure:"read_timeout"`
	ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout"`
	RequestTimeout    time.Duration `mapstructure:"request_timeout"`
}

type DatabaseConfig struct {
	Driver   string `mapstructure:"driver"`
	DSN      string `mapstructure:"dsn"`
	LogLevel int    `mapstructure:"log_level"`
}

func InitConfig(configPath string, env string) (err error) {

	viper.AddConfigPath(configPath)
	viper.SetConfigName(env)
	viper.SetConfigType("yaml")

	viper.SetEnvPrefix("GOUNO")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err = viper.ReadInConfig(); err != nil {
		log.Fatalf("read config failed, err: %v", err)
		return
	}

	if err = viper.Unmarshal(&GlobalConfig); err != nil {
		log.Fatalf("unmarshal config failed, err: %v", err)
		return
	}

	return
}
