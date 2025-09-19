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
	Debug             bool          `mapstructure:"debug"`
	Address           string        `mapstructure:"address"`
	Port              string        `mapstructure:"port"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	ReadTimeout       time.Duration `mapstructure:"read_timeout"`
	ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout"`
	RequestTimeout    time.Duration `mapstructure:"request_timeout"`
}

type DatabaseConfigDriverName string
type DatabaseConfigDriver struct {
	Name     DatabaseConfigDriverName `mapstructure:"name"`
	Driver   string                   `mapstructure:"driver"`
	DSN      string                   `mapstructure:"dsn"`
	LogLevel int                      `mapstructure:"log_level"`
}

type DatabaseConfig struct {
	Default DatabaseConfigDriverName                          `mapstructure:"default"`
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
	FlushSize uint32 `mapstructure:"flush_size"`
	// BufferSize 缓冲通道的容量
	BufferSize uint32 `mapstructure:"buffer_size"`
	// FlushInterval 定时刷新的时间间隔
	FlushInterval time.Duration `mapstructure:"flush_interval"`
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
