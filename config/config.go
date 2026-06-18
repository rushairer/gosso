package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"
)

// GoUnoConfig is the top-level application configuration loaded from YAML and
// environment variables (prefix GOUNO_). It is populated by ConfigManager and
// validated before the application starts.
type GoUnoConfig struct {
	WebServerConfig    WebServerConfig      `mapstructure:"web_server"`
	DatabaseConfig     DatabaseConfig       `mapstructure:"database"`
	RedisConfig        RedisConfig          `mapstructure:"redis"`
	TaskPipelineConfig TaskPipelineConfig   `mapstructure:"task_pipeline"`
	SMTPConfig         SMTPConfig           `mapstructure:"smtp"`
	LogConfig          LogConfig            `mapstructure:"log"`
	AuthConfig         AuthConfig           `mapstructure:"auth"`
	CORSConfig         CORSConfig           `mapstructure:"cors"`
	OAuthProviders     OAuthProvidersConfig `mapstructure:"oauth_providers"`
}

// WebServerConfig holds Gin HTTP server settings including timeouts,
// body-size limits, trusted proxies, and per-endpoint rate limits.
type WebServerConfig struct {
	Debug             bool             `mapstructure:"debug"`
	Address           string           `mapstructure:"address"`
	Port              string           `mapstructure:"port"`
	IdleTimeout       time.Duration    `mapstructure:"idle_timeout"`
	ReadTimeout       time.Duration    `mapstructure:"read_timeout"`
	ReadHeaderTimeout time.Duration    `mapstructure:"read_header_timeout"`
	WriteTimeout      time.Duration    `mapstructure:"write_timeout"`
	RequestTimeout    time.Duration    `mapstructure:"request_timeout"`
	ShutdownTimeout   time.Duration    `mapstructure:"shutdown_timeout"`
	MaxBodySize       int64            `mapstructure:"max_body_size"`
	TrustedProxies    []string         `mapstructure:"trusted_proxies"`
	RateLimits        RateLimitsConfig `mapstructure:"rate_limits"`
}

// RateLimitsConfig per-endpoint rate limit configuration (requests per minute)
type RateLimitsConfig struct {
	Login      int `mapstructure:"login"`       // Login endpoint, default 5
	Token      int `mapstructure:"token"`       // Token endpoint, default 10
	Passkey    int `mapstructure:"passkey"`     // Passkey endpoint, default 10
	API        int `mapstructure:"api"`         // General API, default 60
	Admin      int `mapstructure:"admin"`       // Admin endpoint, default 30
	Introspect int `mapstructure:"introspect"`  // Introspect endpoint, default 20
	DeviceCode int `mapstructure:"device_code"` // Device code endpoint, default 10
	Password   int `mapstructure:"password"`    // Password reset endpoint, default 3
	Verify     int `mapstructure:"verify"`      // Verification code endpoint, default 3
}

// DatabaseConfigDriverName is a named key for a database driver
// (e.g. "postgres").
type DatabaseConfigDriverName string

// DatabaseConfigDriver describes a single database driver entry including its
// Go driver name, DSN, and ORM log level.
type DatabaseConfigDriver struct {
	Name     DatabaseConfigDriverName `mapstructure:"name"`
	Driver   string                   `mapstructure:"driver"`
	DSN      string                   `mapstructure:"dsn"`
	LogLevel int                      `mapstructure:"log_level"`
}

// DatabaseConfig holds connection-pool tuning and the set of named database
// drivers. Exactly one driver must be marked as Default.
type DatabaseConfig struct {
	Default              DatabaseConfigDriverName                          `mapstructure:"default"`
	Drivers              map[DatabaseConfigDriverName]DatabaseConfigDriver `mapstructure:"drivers"`
	MaxOpenConns         int                                               `mapstructure:"max_open_conns"`
	MaxIdleConns         int                                               `mapstructure:"max_idle_conns"`
	ConnMaxLifetimeSec   int                                               `mapstructure:"conn_max_lifetime_sec"`
	ConnMaxIdleTimeSec   int                                               `mapstructure:"conn_max_idle_time_sec"`
	PoolStatsIntervalSec int                                               `mapstructure:"pool_stats_interval_sec"` // 0 disables periodic pool stats logging
}

// GetDriver returns a pointer to the named database driver config, or nil if not found.
// Note: the returned pointer targets a local copy of the map value (safe since Go 1.22+
// gives each range iteration its own variable; the map value is not addressable directly).
func (c DatabaseConfig) GetDriver(name DatabaseConfigDriverName) *DatabaseConfigDriver {
	if driver, ok := c.Drivers[name]; ok {
		return &driver
	}
	return nil
}

// GetDefaultDriver returns a pointer to the default database driver config, or nil if not found.
func (c DatabaseConfig) GetDefaultDriver() *DatabaseConfigDriver {
	if driver, ok := c.Drivers[c.Default]; ok {
		return &driver
	}
	return nil
}

// RedisConfig holds the Redis connection DSN and pool parameters.
type RedisConfig struct {
	DSN                string `mapstructure:"dsn"`
	MaxActiveConns     int    `mapstructure:"max_active_conns"`
	PoolTimeoutSeconds int    `mapstructure:"pool_timeout_seconds"`
}

// TaskPipelineConfig configures the async batch-processing pipeline used by
// background workers (e.g. audit logging).
type TaskPipelineConfig struct {
	// FlushSize is the maximum capacity for batch processing
	FlushSize uint32 `mapstructure:"flush_size"`
	// BufferSize is the capacity of the buffered channel
	BufferSize uint32 `mapstructure:"buffer_size"`
	// FlushInterval is the time interval for periodic flushing
	FlushInterval time.Duration `mapstructure:"flush_interval"`

	// Retry and concurrency tuning (0 = use built-in defaults)
	Timeout     time.Duration `mapstructure:"timeout"`
	MaxAttempts int           `mapstructure:"max_attempts"`
	BackoffBase time.Duration `mapstructure:"backoff_base"`
	MaxBackoff  time.Duration `mapstructure:"max_backoff"`
	Concurrency int           `mapstructure:"concurrency"`
}

// SMTPConfig holds outbound email (SMTP) settings used for password-reset
// and verification emails. When Host is empty the email subsystem is disabled.
type SMTPConfig struct {
	Host          string        `mapstructure:"host"`
	Port          int           `mapstructure:"port"`
	Username      string        `mapstructure:"username"`
	Password      string        `mapstructure:"password" json:"-"`
	From          string        `mapstructure:"from"`
	TLSPolicy     string        `mapstructure:"tls_policy"`
	SendRateLimit time.Duration `mapstructure:"send_rate_limit"` // minimum interval between sends (0 = 100ms default)
}

// LogConfig holds logging configuration.
type LogConfig struct {
	// Log level: -1: debug, 0: info, 1: warn, 2: error, 3: dpanic, 4: panic, 5: fatal
	Level int `mapstructure:"level"`
	// Log format: "console" (default) or "json" (for containerized/production environments)
	Format string `mapstructure:"format"`
}

// AuthConfig holds authentication and authorization settings including token
// lifetimes, OAuth2/OIDC issuer, WebAuthn parameters, MFA defaults, and
// rate-limiting knobs for login, password reset, and verification flows.
type AuthConfig struct {
	Issuer                  string        `mapstructure:"issuer"`
	AccessTokenExpiry       time.Duration `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry      time.Duration `mapstructure:"refresh_token_expiry"`
	SessionTTL              time.Duration `mapstructure:"session_ttl"`
	MaxSessions             int           `mapstructure:"max_sessions"`
	MaxSessionAge           time.Duration `mapstructure:"max_session_age"`
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
	TOTPEncryptionKey       string        `mapstructure:"totp_encryption_key" json:"-"`

	// Login rate limiting (0 = use built-in defaults)
	LoginRateLimitWindow  time.Duration `mapstructure:"login_rate_limit_window"`
	LoginMaxAttempts      int           `mapstructure:"login_max_attempts"`
	LoginMaxAttemptsPerIP int           `mapstructure:"login_max_attempts_per_ip"`

	// MFA settings (0 = use built-in defaults)
	MFAVerificationTTL time.Duration `mapstructure:"mfa_verification_ttl"`
	ChallengeTTL       time.Duration `mapstructure:"challenge_ttl"`
	BackupCodeCount    int           `mapstructure:"backup_code_count"`
	BackupCodeLength   int           `mapstructure:"backup_code_length"`

	// Password reset settings (0 = use built-in defaults)
	PasswordResetWaitTimeout       time.Duration `mapstructure:"password_reset_wait_timeout"`
	PasswordResetTokenTTL          time.Duration `mapstructure:"password_reset_token_ttl"`
	PasswordResetCooldownTTL       time.Duration `mapstructure:"password_reset_cooldown_ttl"`
	PasswordResetMaxAttempts       int           `mapstructure:"password_reset_max_attempts"`
	PasswordResetRevokeConcurrency int           `mapstructure:"password_reset_revoke_concurrency"`

	// Verification code settings (0 = use built-in defaults)
	VerifyCodeTTL         time.Duration `mapstructure:"verify_code_ttl"`
	VerifyCooldownTTL     time.Duration `mapstructure:"verify_cooldown_ttl"`
	VerifyCodeMaxAttempts int           `mapstructure:"verify_code_max_attempts"`

	// OIDC settings
	IDTokenExpiry time.Duration `mapstructure:"id_token_expiry"`

	// Social login HTTP client timeout (0 = 10s default)
	SocialLoginHTTPTimeout time.Duration `mapstructure:"social_login_http_timeout"`

	// CSRF cookie lifetime (0 = 4h default)
	CSRFCookieMaxAge time.Duration `mapstructure:"csrf_cookie_max_age"`

	// RSA key size in bits for new key generation (0 = 3072 default)
	RSAKeyBits int `mapstructure:"rsa_key_bits"`
}

// CORSConfig configures Cross-Origin Resource Sharing (CORS) headers.
type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

// OAuthProviderConfig describes a single external OAuth 2.0 identity provider
// (e.g. Google, GitHub, WeChat).
type OAuthProviderConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret" json:"-"`
	RedirectURI  string   `mapstructure:"redirect_uri"`
	Scopes       []string `mapstructure:"scopes"`
	AuthURL      string   `mapstructure:"auth_url"`
	TokenURL     string   `mapstructure:"token_url"`
	UserInfoURL  string   `mapstructure:"userinfo_url"`
}

// OAuthProvidersConfig aggregates all configured social-login providers.
type OAuthProvidersConfig struct {
	Google OAuthProviderConfig `mapstructure:"google"`
	GitHub OAuthProviderConfig `mapstructure:"github"`
	WeChat OAuthProviderConfig `mapstructure:"wechat"`
}

// Validate checks that critical configuration values are present and valid.
// It accumulates all validation errors across sections and returns them joined,
// so that callers can fix all issues in one pass instead of one at a time.
func (c *GoUnoConfig) Validate() error {
	var errs []error
	if err := c.validateWebServer(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateLog(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateDatabase(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateRedis(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateAuth(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateSMTP(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateCORS(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateOAuthProviders(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (c *GoUnoConfig) validateWebServer() error {
	if c.WebServerConfig.Port == "" {
		return fmt.Errorf("web_server: port is required")
	}
	var port int
	if _, err := fmt.Sscanf(c.WebServerConfig.Port, "%d", &port); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("web_server: port must be a valid port number (1-65535), got %q", c.WebServerConfig.Port)
	}
	if c.WebServerConfig.MaxBodySize <= 0 {
		return fmt.Errorf("web_server: max_body_size must be positive (got %d)", c.WebServerConfig.MaxBodySize)
	}
	if c.WebServerConfig.ReadTimeout <= 0 {
		return fmt.Errorf("web_server: read_timeout must be positive")
	}
	if c.WebServerConfig.WriteTimeout <= 0 {
		return fmt.Errorf("web_server: write_timeout must be positive")
	}
	if c.WebServerConfig.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("web_server: read_header_timeout must be positive")
	}
	if c.WebServerConfig.IdleTimeout <= 0 {
		return fmt.Errorf("web_server: idle_timeout must be positive")
	}
	if c.WebServerConfig.RequestTimeout <= 0 {
		return fmt.Errorf("web_server: request_timeout must be positive")
	}
	if c.WebServerConfig.ShutdownTimeout <= 0 {
		return fmt.Errorf("web_server: shutdown_timeout must be positive")
	}
	if !c.WebServerConfig.Debug && len(c.WebServerConfig.TrustedProxies) == 0 {
		return fmt.Errorf("web_server: trusted_proxies must not be empty in production (set to proxy CIDRs, e.g. [\"172.22.0.0/16\"])")
	}
	rl := c.WebServerConfig.RateLimits
	if rl.Login <= 0 {
		return fmt.Errorf("web_server: rate_limits.login must be positive (got %d)", rl.Login)
	}
	if rl.Token <= 0 {
		return fmt.Errorf("web_server: rate_limits.token must be positive (got %d)", rl.Token)
	}
	if rl.Passkey <= 0 {
		return fmt.Errorf("web_server: rate_limits.passkey must be positive (got %d)", rl.Passkey)
	}
	if rl.API <= 0 {
		return fmt.Errorf("web_server: rate_limits.api must be positive (got %d)", rl.API)
	}
	if rl.Admin <= 0 {
		return fmt.Errorf("web_server: rate_limits.admin must be positive (got %d)", rl.Admin)
	}
	if rl.Introspect <= 0 {
		return fmt.Errorf("web_server: rate_limits.introspect must be positive (got %d)", rl.Introspect)
	}
	if rl.DeviceCode <= 0 {
		return fmt.Errorf("web_server: rate_limits.device_code must be positive (got %d)", rl.DeviceCode)
	}
	if rl.Password <= 0 {
		return fmt.Errorf("web_server: rate_limits.password must be positive (got %d)", rl.Password)
	}
	if rl.Verify <= 0 {
		return fmt.Errorf("web_server: rate_limits.verify must be positive (got %d)", rl.Verify)
	}
	return nil
}

func (c *GoUnoConfig) validateLog() error {
	if c.LogConfig.Level < -1 || c.LogConfig.Level > 5 {
		return fmt.Errorf("log: level must be between -1 (debug) and 5 (fatal), got %d", c.LogConfig.Level)
	}
	if c.LogConfig.Format != "" && c.LogConfig.Format != "console" && c.LogConfig.Format != "json" {
		return fmt.Errorf("log: format must be \"console\" or \"json\", got %q", c.LogConfig.Format)
	}
	return nil
}

func (c *GoUnoConfig) validateDatabase() error {
	if c.DatabaseConfig.GetDefaultDriver() == nil {
		return fmt.Errorf("database: no default driver configured")
	}
	if c.DatabaseConfig.GetDefaultDriver().DSN == "" {
		return fmt.Errorf("database: default driver DSN is empty")
	}
	if !c.WebServerConfig.Debug && c.DatabaseConfig.GetDefaultDriver().DSN == defaultPostgresDSN {
		return fmt.Errorf("database: default driver DSN must be explicitly configured in production (the development default is not allowed)")
	}
	if c.DatabaseConfig.ConnMaxLifetimeSec < 0 {
		return fmt.Errorf("database: conn_max_lifetime_sec must not be negative (got %d)", c.DatabaseConfig.ConnMaxLifetimeSec)
	}
	if c.DatabaseConfig.ConnMaxIdleTimeSec < 0 {
		return fmt.Errorf("database: conn_max_idle_time_sec must not be negative (got %d)", c.DatabaseConfig.ConnMaxIdleTimeSec)
	}
	if c.DatabaseConfig.MaxOpenConns <= 0 {
		return fmt.Errorf("database: max_open_conns must be positive (got %d)", c.DatabaseConfig.MaxOpenConns)
	}
	if c.DatabaseConfig.MaxIdleConns <= 0 {
		return fmt.Errorf("database: max_idle_conns must be positive (got %d); set to at least max_open_conns/4", c.DatabaseConfig.MaxIdleConns)
	}
	if c.DatabaseConfig.MaxIdleConns > c.DatabaseConfig.MaxOpenConns {
		return fmt.Errorf("database: max_idle_conns (%d) must not exceed max_open_conns (%d)",
			c.DatabaseConfig.MaxIdleConns, c.DatabaseConfig.MaxOpenConns)
	}
	return nil
}

func (c *GoUnoConfig) validateRedis() error {
	if c.RedisConfig.DSN == "" {
		return fmt.Errorf("redis: DSN is empty (hint: set GOUNO_REDIS_DSN environment variable)")
	}
	if c.RedisConfig.MaxActiveConns <= 0 {
		return fmt.Errorf("redis: max_active_conns must be positive (got %d)", c.RedisConfig.MaxActiveConns)
	}
	if c.RedisConfig.PoolTimeoutSeconds <= 0 {
		return fmt.Errorf("redis: pool_timeout_seconds must be positive (got %d)", c.RedisConfig.PoolTimeoutSeconds)
	}
	return nil
}

func (c *GoUnoConfig) validateAuth() error {
	if c.AuthConfig.Issuer == "" {
		return fmt.Errorf("auth: issuer is empty")
	}
	issuerURL, err := url.Parse(c.AuthConfig.Issuer)
	if err != nil || (issuerURL.Scheme != "http" && issuerURL.Scheme != "https") {
		return fmt.Errorf("auth: issuer must be a valid URL with http or https scheme")
	}
	if !c.WebServerConfig.Debug {
		if issuerURL.Scheme != "https" {
			return fmt.Errorf("auth: issuer must use https in production")
		}
		switch issuerURL.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return fmt.Errorf("auth: issuer must not point to localhost in production")
		}
	}
	if c.AuthConfig.TOTPEncryptionKey == "" {
		return fmt.Errorf("auth: totp_encryption_key is required")
	}
	key, err := hex.DecodeString(c.AuthConfig.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("auth: totp_encryption_key must be a valid hex string")
	}
	if len(key) != 32 {
		return fmt.Errorf("auth: totp_encryption_key must decode to exactly 32 bytes (got %d)", len(key))
	}
	if !c.WebServerConfig.Debug && c.AuthConfig.TOTPEncryptionKey == defaultTOTPEncryptionKey {
		return fmt.Errorf("auth: totp_encryption_key must be explicitly configured in production (the development default is not allowed)")
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
	if c.AuthConfig.PrivateKeyPath != "" {
		if stat, err := os.Stat(c.AuthConfig.PrivateKeyPath); err != nil {
			if os.IsNotExist(err) {
				if !c.WebServerConfig.Debug {
					return fmt.Errorf("auth: private_key_path file does not exist: %s", c.AuthConfig.PrivateKeyPath)
				}
			} else {
				return fmt.Errorf("auth: cannot access private_key_path: %w", err)
			}
		} else if stat.IsDir() {
			return fmt.Errorf("auth: private_key_path is a directory, not a file: %s", c.AuthConfig.PrivateKeyPath)
		}
	}
	if c.AuthConfig.MaxSessions <= 0 {
		return fmt.Errorf("auth: max_sessions must be positive")
	}
	// Validate optional TTL fields — zero means "use built-in default", but negative is always wrong.
	if c.AuthConfig.MaxSessionAge < 0 {
		return fmt.Errorf("auth: max_session_age must not be negative (got %s)", c.AuthConfig.MaxSessionAge)
	}
	if c.AuthConfig.MFAVerificationTTL < 0 {
		return fmt.Errorf("auth: mfa_verification_ttl must not be negative (got %s)", c.AuthConfig.MFAVerificationTTL)
	}
	if c.AuthConfig.PasswordResetTokenTTL < 0 {
		return fmt.Errorf("auth: password_reset_token_ttl must not be negative (got %s)", c.AuthConfig.PasswordResetTokenTTL)
	}
	if c.AuthConfig.PasswordResetCooldownTTL < 0 {
		return fmt.Errorf("auth: password_reset_cooldown_ttl must not be negative (got %s)", c.AuthConfig.PasswordResetCooldownTTL)
	}
	if c.AuthConfig.VerifyCodeTTL < 0 {
		return fmt.Errorf("auth: verify_code_ttl must not be negative (got %s)", c.AuthConfig.VerifyCodeTTL)
	}
	if c.AuthConfig.VerifyCooldownTTL < 0 {
		return fmt.Errorf("auth: verify_cooldown_ttl must not be negative (got %s)", c.AuthConfig.VerifyCooldownTTL)
	}
	if c.AuthConfig.WebAuthnRPID != "" {
		if c.AuthConfig.WebAuthnRPName == "" {
			return fmt.Errorf("auth: webauthn_rp_name is required when webauthn_rp_id is set")
		}
		if c.AuthConfig.WebAuthnRPOrigin == "" {
			return fmt.Errorf("auth: webauthn_rp_origin is required when webauthn_rp_id is set")
		}
		origin, err := url.Parse(c.AuthConfig.WebAuthnRPOrigin)
		if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") {
			return fmt.Errorf("auth: webauthn_rp_origin must be a valid URL with http or https scheme")
		}
		if origin.Scheme == "http" && origin.Hostname() != "localhost" && origin.Hostname() != "127.0.0.1" {
			return fmt.Errorf("auth: webauthn_rp_origin with http scheme is only allowed for localhost or 127.0.0.1")
		}
		if origin.Path != "" && origin.Path != "/" {
			return fmt.Errorf("auth: webauthn_rp_origin must not contain a path component (got %q)", origin.Path)
		}
		if origin.Fragment != "" {
			return fmt.Errorf("auth: webauthn_rp_origin must not contain a fragment")
		}
	}
	return nil
}

func (c *GoUnoConfig) validateSMTP() error {
	if c.SMTPConfig.Host != "" {
		if c.SMTPConfig.Port <= 0 {
			return fmt.Errorf("smtp: port must be positive when host is configured (check GOUNO_SMTP_PORT environment variable)")
		}
		if c.SMTPConfig.From == "" {
			return fmt.Errorf("smtp: from address is required when host is configured")
		}
		switch c.SMTPConfig.TLSPolicy {
		case "", "opportunistic", "mandatory", "notls":
			// valid (empty defaults to opportunistic)
		default:
			return fmt.Errorf("smtp: tls_policy must be one of: opportunistic, mandatory, notls (got %q)", c.SMTPConfig.TLSPolicy)
		}
		if !c.WebServerConfig.Debug && c.SMTPConfig.TLSPolicy == "notls" {
			return fmt.Errorf("smtp: tls_policy 'notls' is not allowed in production (set GOUNO_SMTP_TLS_POLICY=mandatory)")
		}
		if c.AuthConfig.PasswordResetBaseURL == "" {
			return fmt.Errorf("auth: password_reset_base_url is required when SMTP is configured")
		}
		resetURL, err := url.Parse(c.AuthConfig.PasswordResetBaseURL)
		if err != nil || (resetURL.Scheme != "http" && resetURL.Scheme != "https") {
			return fmt.Errorf("auth: password_reset_base_url must be a valid URL with http or https scheme")
		}
	}
	return nil
}

func (c *GoUnoConfig) validateCORS() error {
	if c.CORSConfig.MaxAge < 0 {
		return fmt.Errorf("cors: max_age must not be negative (got %d)", c.CORSConfig.MaxAge)
	}
	if c.CORSConfig.AllowCredentials {
		for _, origin := range c.CORSConfig.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("cors: allow_credentials cannot be used with wildcard origin '*'")
			}
		}
	}
	return nil
}

func (c *GoUnoConfig) validateOAuthProviders() error {
	var errs []error
	for name, provider := range map[string]OAuthProviderConfig{
		"google": c.OAuthProviders.Google,
		"github": c.OAuthProviders.GitHub,
		"wechat": c.OAuthProviders.WeChat,
	} {
		// Skip validation for providers that aren't configured.
		if provider.ClientID == "" && provider.ClientSecret == "" {
			continue
		}
		if provider.ClientID == "" {
			errs = append(errs, fmt.Errorf("oauth_providers.%s: client_id is required when client_secret is set", name))
		}
		if provider.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("oauth_providers.%s: client_secret is required when client_id is set", name))
		}
		if provider.RedirectURI != "" {
			redirectURL, err := url.Parse(provider.RedirectURI)
			if err != nil || (redirectURL.Scheme != "http" && redirectURL.Scheme != "https") {
				errs = append(errs, fmt.Errorf("oauth_providers.%s: redirect_uri must be a valid URL with http or https scheme", name))
			}
		}
	}
	return errors.Join(errs...)
}
