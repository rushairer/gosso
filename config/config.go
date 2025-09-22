package config

import (
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var GlobalConfig GoUnoConfig

type GoUnoConfig struct {
	WebServerConfig    WebServerConfig    `mapstructure:"web_server"`
	DatabaseConfig     DatabaseConfig     `mapstructure:"database"`
	TaskPipelineConfig TaskPipelineConfig `mapstructure:"task_pipeline"`
}

type WebServerConfig struct {
	Debug              bool          `mapstructure:"debug" default:"false"`
	Address            string        `mapstructure:"address" default:"0.0.0.0"`
	Port               string        `mapstructure:"port" default:"8080"`
	IdleTimeout        time.Duration `mapstructure:"idle_timeout" default:"60s"`
	ReadTimeout        time.Duration `mapstructure:"read_timeout" default:"5s"`
	ReadHeaderTimeout  time.Duration `mapstructure:"read_header_timeout" default:"2s"`
	WriteTimeout       time.Duration `mapstructure:"write_timeout" default:"30s"`
	RequestTimeout     time.Duration `mapstructure:"request_timeout" default:"10s"`
	RateLimitPerMinute int           `mapstructure:"rate_limit_per_minute" default:"100"`
}

type DatabaseConfigDriverName string
type DatabaseConfigDriver struct {
	Name     DatabaseConfigDriverName `mapstructure:"name" default:"sqlite"`
	Driver   string                   `mapstructure:"driver" default:"sqlite3"`
	DSN      string                   `mapstructure:"dsn" default:":memory:"`
	LogLevel int                      `mapstructure:"log_level" default:"1"`
}

type DatabaseConfig struct {
	Default DatabaseConfigDriverName                          `mapstructure:"default" default:"sqlite"`
	Drivers map[DatabaseConfigDriverName]DatabaseConfigDriver `mapstructure:"drivers"`
}

func (c *DatabaseConfig) GetDriver(name DatabaseConfigDriverName) *DatabaseConfigDriver {
	if driver, ok := c.Drivers[name]; ok {
		return &driver
	} else {
		return nil
	}
}

func (c *DatabaseConfig) GetDefaultDriver() *DatabaseConfigDriver {
	if driver, ok := c.Drivers[c.Default]; ok {
		return &driver
	} else {
		return nil
	}
}

type TaskPipelineConfig struct {
	// FlushSize 批处理数据的最大容量
	FlushSize uint32 `mapstructure:"flush_size" default:"32"`
	// BufferSize 缓冲通道的容量
	BufferSize uint32 `mapstructure:"buffer_size" default:"64"`
	// FlushInterval 定时刷新的时间间隔
	FlushInterval time.Duration `mapstructure:"flush_interval" default:"1s"`
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
