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
	SMTPConfig         SMTPConfig         `mapstructure:"smtp"`
	CaptchaType        string             `mapstructure:"captcha_type"`
}

type WebServerConfig struct {
	Debug              bool          `mapstructure:"debug"`
	Address            string        `mapstructure:"address"`
	Port               string        `mapstructure:"port"`
	IdleTimeout        time.Duration `mapstructure:"idle_timeout"`
	ReadTimeout        time.Duration `mapstructure:"read_timeout"`
	ReadHeaderTimeout  time.Duration `mapstructure:"read_header_timeout"`
	WriteTimeout       time.Duration `mapstructure:"write_timeout"`
	RequestTimeout     time.Duration `mapstructure:"request_timeout"`
	RateLimitPerMinute int           `mapstructure:"rate_limit_per_minute"`
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

type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
}

func InitConfig(configPath string, env string) (err error) {
	// 设置所有默认值
	setConfigDefaults()

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

func setConfigDefaults() {
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

	// 任务管道配置
	viper.SetDefault("task_pipeline.flush_size", 32)
	viper.SetDefault("task_pipeline.buffer_size", 64)
	viper.SetDefault("task_pipeline.flush_interval", "1s")

	// SMTP配置
	viper.SetDefault("smtp.host", "localhost")
	viper.SetDefault("smtp.port", 1025)
	viper.SetDefault("smtp.username", "")
	viper.SetDefault("smtp.password", "")
	viper.SetDefault("smtp.from", "noreply@gosso.local")
}
