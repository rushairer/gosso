package config

import (
	"fmt"
	"time"
)

type GoUnoConfig struct {
	WebServerConfig    WebServerConfig      `mapstructure:"web_server"`
	DatabaseConfig     DatabaseConfig       `mapstructure:"database"`
	RedisConfig        RedisConfig          `mapstructure:"redis"`
	TaskPipelineConfig TaskPipelineConfig   `mapstructure:"task_pipeline"`
	SMTPConfig         SMTPConfig           `mapstructure:"smtp"`
	CaptchaConfig      CaptchaConfig        `mapstructure:"captcha"`
	LogConfig          LogConfig            `mapstructure:"log"`
	AuthConfig         AuthConfig           `mapstructure:"auth"`
	CORSConfig         CORSConfig           `mapstructure:"cors"`
	OAuthProviders     OAuthProvidersConfig `mapstructure:"oauth_providers"`
}

type WebServerConfig struct {
	Debug              bool             `mapstructure:"debug"`
	Address            string           `mapstructure:"address"`
	Port               string           `mapstructure:"port"`
	IdleTimeout        time.Duration    `mapstructure:"idle_timeout"`
	ReadTimeout        time.Duration    `mapstructure:"read_timeout"`
	ReadHeaderTimeout  time.Duration    `mapstructure:"read_header_timeout"`
	WriteTimeout       time.Duration    `mapstructure:"write_timeout"`
	RequestTimeout     time.Duration    `mapstructure:"request_timeout"`
	RateLimitPerMinute int              `mapstructure:"rate_limit_per_minute"`
	RateLimits         RateLimitsConfig `mapstructure:"rate_limits"`
}

// RateLimitsConfig per-endpoint rate limit configuration (requests per minute)
type RateLimitsConfig struct {
	Login   int `mapstructure:"login"`   // Login endpoint, default 5
	Token   int `mapstructure:"token"`   // Token endpoint, default 10
	Passkey int `mapstructure:"passkey"` // Passkey endpoint, default 10
	API     int `mapstructure:"api"`     // General API, default 60
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

type RedisConfig struct {
	DSN                string `mapstructure:"dsn"`
	MaxActiveConns     int    `mapstructure:"max_active_conns"`
	PoolTimeoutSeconds int    `mapstructure:"pool_timeout_seconds"`
}

type TaskPipelineConfig struct {
	// FlushSize is the maximum capacity for batch processing
	FlushSize uint32 `mapstructure:"flush_size"`
	// BufferSize is the capacity of the buffered channel
	BufferSize uint32 `mapstructure:"buffer_size"`
	// FlushInterval is the time interval for periodic flushing
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
	// Log level: -1: debug, 0: info, 1: warn, 2: error, 3: fatal, 4: panic, 5: fatal
	Level int `mapstructure:"level"`
}

type AuthConfig struct {
	JWTSecret               string        `mapstructure:"jwt_secret"`
	Issuer                  string        `mapstructure:"issuer"`
	AccessTokenExpiry       time.Duration `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry      time.Duration `mapstructure:"refresh_token_expiry"`
	AuthorizationCodeExpiry time.Duration `mapstructure:"authorization_code_expiry"`
	DeviceCodeExpiry        time.Duration `mapstructure:"device_code_expiry"`
	DeviceCodeInterval      time.Duration `mapstructure:"device_code_interval"`
	DefaultScopes           []string      `mapstructure:"default_scopes"`
	PrivateKeyPath          string        `mapstructure:"private_key_path"`
	KeyID                   string        `mapstructure:"key_id"`
	PasswordResetBaseURL    string        `mapstructure:"password_reset_base_url"`
	WebAuthnRPID            string        `mapstructure:"webauthn_rp_id"`
	WebAuthnRPName          string        `mapstructure:"webauthn_rp_name"`
	WebAuthnRPOrigin        string        `mapstructure:"webauthn_rp_origin"`
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

type OAuthProviderConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURI  string   `mapstructure:"redirect_uri"`
	Scopes       []string `mapstructure:"scopes"`
	AuthURL      string   `mapstructure:"auth_url"`
	TokenURL     string   `mapstructure:"token_url"`
	UserInfoURL  string   `mapstructure:"userinfo_url"`
}

type OAuthProvidersConfig struct {
	Google OAuthProviderConfig `mapstructure:"google"`
	GitHub OAuthProviderConfig `mapstructure:"github"`
	WeChat OAuthProviderConfig `mapstructure:"wechat"`
}

// Validate checks that critical configuration values are present and valid.
func (c *GoUnoConfig) Validate() error {
	if c.DatabaseConfig.GetDefaultDriver() == nil {
		return fmt.Errorf("database: no default driver configured")
	}
	if c.DatabaseConfig.GetDefaultDriver().DSN == "" {
		return fmt.Errorf("database: default driver DSN is empty")
	}
	if c.RedisConfig.DSN == "" {
		return fmt.Errorf("redis: DSN is empty")
	}
	if c.AuthConfig.Issuer == "" {
		return fmt.Errorf("auth: issuer is empty")
	}
	if c.AuthConfig.JWTSecret == "" {
		return fmt.Errorf("auth: jwt_secret is empty")
	}
	if c.AuthConfig.AccessTokenExpiry <= 0 {
		return fmt.Errorf("auth: access_token_expiry must be positive")
	}
	if c.AuthConfig.RefreshTokenExpiry <= 0 {
		return fmt.Errorf("auth: refresh_token_expiry must be positive")
	}
	if c.WebServerConfig.RateLimits.Login < 0 || c.WebServerConfig.RateLimits.Token < 0 ||
		c.WebServerConfig.RateLimits.Passkey < 0 || c.WebServerConfig.RateLimits.API < 0 {
		return fmt.Errorf("web_server: rate_limits values must be non-negative")
	}
	return nil
}
