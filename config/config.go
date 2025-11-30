package config

import (
	"time"
)

type GoUnoConfig struct {
	WebServerConfig    WebServerConfig    `mapstructure:"web_server"`
	DatabaseConfig     DatabaseConfig     `mapstructure:"database"`
	BigCacheConfig     BigCacheConfig     `mapstructure:"bigcache"`
	RedisConfig        RedisConfig        `mapstructure:"redis"`
	TaskPipelineConfig TaskPipelineConfig `mapstructure:"task_pipeline"`
	SMTPConfig         SMTPConfig         `mapstructure:"smtp"`
	CaptchaConfig      CaptchaConfig      `mapstructure:"captcha"`
	LogConfig          LogConfig          `mapstructure:"log"`
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

func (c DatabaseConfig) GetDriver(name DatabaseConfigDriverName) *DatabaseConfigDriver {
	if driver, ok := c.Drivers[name]; ok {
		return &driver
	} else {
		return nil
	}
}

func (c DatabaseConfig) GetDefaultDriver() *DatabaseConfigDriver {
	if driver, ok := c.Drivers[c.Default]; ok {
		return &driver
	} else {
		return nil
	}
}

type BigCacheConfig struct {
	HardMaxCacheSize int `mapstructure:"hard_max_cache_size"`
}

type RedisConfig struct {
	DSN                string `mapstructure:"dsn"`
	MaxActiveConns     int    `mapstructure:"max_active_conns"`
	PoolTimeoutSeconds int    `mapstructure:"pool_timeout_seconds"`
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

type CaptchaConfig struct {
	Type string `mapstructure:"type"`
}

type LogConfig struct {
	// 日志级别: -1: debug, 0: info, 1: warn, 2: error, 3: fatal, 4: panic 5: fatal
	Level int `mapstructure:"level"`
}
