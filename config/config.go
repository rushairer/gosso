package config

import (
	"encoding/hex"
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
	MaxBodySize        int64            `mapstructure:"max_body_size"`
	RateLimits         RateLimitsConfig `mapstructure:"rate_limits"`
}

// RateLimitsConfig per-endpoint rate limit configuration (requests per minute)
type RateLimitsConfig struct {
	Login      int `mapstructure:"login"`       // Login endpoint, default 5
	Token      int `mapstructure:"token"`       // Token endpoint, default 10
	Passkey    int `mapstructure:"passkey"`     // Passkey endpoint, default 10
	API        int `mapstructure:"api"`         // General API, default 60
	Introspect int `mapstructure:"introspect"`  // Introspect endpoint, default 20
	DeviceCode int `mapstructure:"device_code"` // Device code endpoint, default 10
}

type DatabaseConfigDriverName string

type DatabaseConfigDriver struct {
	Name     DatabaseConfigDriverName `mapstructure:"name"`
	Driver   string                   `mapstructure:"driver"`
	DSN      string                   `mapstructure:"dsn"`
	LogLevel int                      `mapstructure:"log_level"`
}

type DatabaseConfig struct {
	Default            DatabaseConfigDriverName                          `mapstructure:"default"`
	Drivers            map[DatabaseConfigDriverName]DatabaseConfigDriver `mapstructure:"drivers"`
	MaxOpenConns       int                                               `mapstructure:"max_open_conns"`
	MaxIdleConns       int                                               `mapstructure:"max_idle_conns"`
	ConnMaxLifetimeSec int                                               `mapstructure:"conn_max_lifetime_sec"`
	ConnMaxIdleTimeSec int                                               `mapstructure:"conn_max_idle_time_sec"`
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
	// Log level: -1: debug, 0: info, 1: warn, 2: error, 3: dpanic, 4: panic, 5: fatal
	Level int `mapstructure:"level"`
}

type AuthConfig struct {
	JWTSecret               string        `mapstructure:"jwt_secret"`
	Issuer                  string        `mapstructure:"issuer"`
	AccessTokenExpiry       time.Duration `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry      time.Duration `mapstructure:"refresh_token_expiry"`
	SessionTTL              time.Duration `mapstructure:"session_ttl"`
	MaxSessions             int           `mapstructure:"max_sessions"`
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
	TOTPEncryptionKey       string        `mapstructure:"totp_encryption_key"`

	// Login rate limiting (0 = use built-in defaults)
	LoginRateLimitWindow  time.Duration `mapstructure:"login_rate_limit_window"`
	LoginMaxAttempts      int           `mapstructure:"login_max_attempts"`
	LoginMaxAttemptsPerIP int           `mapstructure:"login_max_attempts_per_ip"`

	// MFA settings (0 = use built-in defaults)
	MFAVerificationTTL time.Duration `mapstructure:"mfa_verification_ttl"`
	ChallengeTTL       time.Duration `mapstructure:"challenge_ttl"`
	BackupCodeCount    int           `mapstructure:"backup_code_count"`
	BackupCodeLength   int           `mapstructure:"backup_code_length"`

	// OIDC settings
	IDTokenExpiry time.Duration `mapstructure:"id_token_expiry"`
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
	if len(c.AuthConfig.JWTSecret) < 32 {
		return fmt.Errorf("auth: jwt_secret must be at least 32 characters")
	}
	if c.AuthConfig.TOTPEncryptionKey != "" {
		key, err := hex.DecodeString(c.AuthConfig.TOTPEncryptionKey)
		if err != nil {
			return fmt.Errorf("auth: totp_encryption_key must be a valid hex string")
		}
		if len(key) != 32 {
			return fmt.Errorf("auth: totp_encryption_key must decode to exactly 32 bytes (got %d)", len(key))
		}
	}
	if c.AuthConfig.AccessTokenExpiry <= 0 {
		return fmt.Errorf("auth: access_token_expiry must be positive")
	}
	if c.AuthConfig.RefreshTokenExpiry <= 0 {
		return fmt.Errorf("auth: refresh_token_expiry must be positive")
	}
	if c.AuthConfig.IDTokenExpiry <= 0 {
		return fmt.Errorf("auth: id_token_expiry must be positive")
	}
	if c.AuthConfig.SessionTTL <= 0 {
		return fmt.Errorf("auth: session_ttl must be positive")
	}
	if c.AuthConfig.AuthorizationCodeExpiry <= 0 {
		return fmt.Errorf("auth: authorization_code_expiry must be positive")
	}
	if c.AuthConfig.DeviceCodeExpiry <= 0 {
		return fmt.Errorf("auth: device_code_expiry must be positive")
	}
	if c.AuthConfig.DeviceCodeInterval <= 0 {
		return fmt.Errorf("auth: device_code_interval must be positive")
	}
	if c.WebServerConfig.RateLimits.Login <= 0 || c.WebServerConfig.RateLimits.Token <= 0 ||
		c.WebServerConfig.RateLimits.Passkey <= 0 || c.WebServerConfig.RateLimits.API <= 0 {
		return fmt.Errorf("web_server: rate_limits values must be positive")
	}
	if c.SMTPConfig.Host != "" {
		if c.SMTPConfig.Port <= 0 {
			return fmt.Errorf("smtp: port must be positive when host is configured")
		}
		if c.SMTPConfig.From == "" {
			return fmt.Errorf("smtp: from address is required when host is configured")
		}
		if c.AuthConfig.PasswordResetBaseURL == "" {
			return fmt.Errorf("auth: password_reset_base_url is required when SMTP is configured")
		}
	}
	if c.AuthConfig.WebAuthnRPID != "" {
		if c.AuthConfig.WebAuthnRPName == "" {
			return fmt.Errorf("auth: webauthn_rp_name is required when webauthn_rp_id is set")
		}
		if c.AuthConfig.WebAuthnRPOrigin == "" {
			return fmt.Errorf("auth: webauthn_rp_origin is required when webauthn_rp_id is set")
		}
	}
	return nil
}
