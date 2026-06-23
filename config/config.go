package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
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
	Observability      ObservabilityConfig  `mapstructure:"observability"`
}

type WebServerConfig struct {
	Production        bool             `mapstructure:"production"`
	Debug             bool             `mapstructure:"debug"`
	Address           string           `mapstructure:"address"`
	Port              int              `mapstructure:"port"`
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

type RateLimitsConfig struct {
	Login      int `mapstructure:"login"`
	Token      int `mapstructure:"token"`
	Passkey    int `mapstructure:"passkey"`
	API        int `mapstructure:"api"`
	Admin      int `mapstructure:"admin"`
	Introspect int `mapstructure:"introspect"`
	DeviceCode int `mapstructure:"device_code"`
	Password   int `mapstructure:"password"`
	Verify     int `mapstructure:"verify"`
	Health     int `mapstructure:"health"`
}

type DatabaseConfigDriverName string

type DatabaseConfigDriver struct {
	Name     DatabaseConfigDriverName `mapstructure:"name"`
	Driver   string                   `mapstructure:"driver"`
	DSN      string                   `mapstructure:"dsn"`
	LogLevel int                      `mapstructure:"log_level"`
}

type DatabaseConfig struct {
	Default              DatabaseConfigDriverName                          `mapstructure:"default"`
	Drivers              map[DatabaseConfigDriverName]DatabaseConfigDriver `mapstructure:"drivers"`
	MaxOpenConns         int                                               `mapstructure:"max_open_conns"`
	MaxIdleConns         int                                               `mapstructure:"max_idle_conns"`
	ConnMaxLifetimeSec   int                                               `mapstructure:"conn_max_lifetime_sec"`
	ConnMaxIdleTimeSec   int                                               `mapstructure:"conn_max_idle_time_sec"`
	PoolStatsIntervalSec int                                               `mapstructure:"pool_stats_interval_sec"`
}

func (c DatabaseConfig) GetDriver(name DatabaseConfigDriverName) *DatabaseConfigDriver {
	if driver, ok := c.Drivers[name]; ok {
		return &driver
	}
	return nil
}

func (c DatabaseConfig) GetDefaultDriver() *DatabaseConfigDriver {
	return c.GetDriver(c.Default)
}

type RedisConfig struct {
	DSN                 string `mapstructure:"dsn"`
	MaxActiveConns      int    `mapstructure:"max_active_conns"`
	PoolTimeoutSeconds  int    `mapstructure:"pool_timeout_seconds"`
	DialTimeoutSeconds  int    `mapstructure:"dial_timeout_seconds"`
	ReadTimeoutSeconds  int    `mapstructure:"read_timeout_seconds"`
	WriteTimeoutSeconds int    `mapstructure:"write_timeout_seconds"`
}

type TaskPipelineConfig struct {
	FlushSize     uint32        `mapstructure:"flush_size"`
	BufferSize    uint32        `mapstructure:"buffer_size"`
	FlushInterval time.Duration `mapstructure:"flush_interval"`
	Timeout       time.Duration `mapstructure:"timeout"`
	MaxAttempts   int           `mapstructure:"max_attempts"`
	BackoffBase   time.Duration `mapstructure:"backoff_base"`
	MaxBackoff    time.Duration `mapstructure:"max_backoff"`
	Concurrency   int           `mapstructure:"concurrency"`
}

type SMTPConfig struct {
	Host           string        `mapstructure:"host"`
	Port           int           `mapstructure:"port"`
	Username       string        `mapstructure:"username"`
	Password       string        `mapstructure:"password" json:"-"`
	From           string        `mapstructure:"from"`
	TLSPolicy      string        `mapstructure:"tls_policy"`
	SendRateLimit  time.Duration `mapstructure:"send_rate_limit"`
	TimeoutSeconds int           `mapstructure:"timeout_seconds"`
}

type LogConfig struct {
	Level  int    `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

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
	VerifyHashPepper        string        `mapstructure:"verify_hash_pepper" json:"-"`
	LoginRateLimitWindow    time.Duration `mapstructure:"login_rate_limit_window"`
	LoginMaxAttempts        int           `mapstructure:"login_max_attempts"`
	LoginMaxAttemptsPerIP   int           `mapstructure:"login_max_attempts_per_ip"`
	// LoginIPAllowlist contains IP addresses or CIDR ranges that are exempt from
	// per-IP login rate limiting. Use this for known proxy/NAT exit IPs where
	// multiple legitimate users share the same public IP.
	// Example: ["203.0.113.0/24", "198.51.100.5"]
	// Note: Per-IP+username counters (login_attempts:{ip}:{user}) still apply.
	LoginIPAllowlist               []string      `mapstructure:"login_ip_allowlist"`
	MFAVerificationTTL             time.Duration `mapstructure:"mfa_verification_ttl"`
	ChallengeTTL                   time.Duration `mapstructure:"challenge_ttl"`
	BackupCodeCount                int           `mapstructure:"backup_code_count"`
	BackupCodeLength               int           `mapstructure:"backup_code_length"`
	PasswordResetWaitTimeout       time.Duration `mapstructure:"password_reset_wait_timeout"`
	PasswordResetTokenTTL          time.Duration `mapstructure:"password_reset_token_ttl"`
	PasswordResetCooldownTTL       time.Duration `mapstructure:"password_reset_cooldown_ttl"`
	PasswordResetMaxAttempts       int           `mapstructure:"password_reset_max_attempts"`
	PasswordResetRevokeConcurrency int           `mapstructure:"password_reset_revoke_concurrency"`
	VerifyCodeTTL                  time.Duration `mapstructure:"verify_code_ttl"`
	VerifyCooldownTTL              time.Duration `mapstructure:"verify_cooldown_ttl"`
	VerifyCodeMaxAttempts          int           `mapstructure:"verify_code_max_attempts"`
	IDTokenExpiry                  time.Duration `mapstructure:"id_token_expiry"`
	SocialLoginHTTPTimeout         time.Duration `mapstructure:"social_login_http_timeout"`
	CSRFCookieMaxAge               time.Duration `mapstructure:"csrf_cookie_max_age"`
	RSAKeyBits                     int           `mapstructure:"rsa_key_bits"`
	AccountValidatorCacheTTL       time.Duration `mapstructure:"account_validator_cache_ttl"`
	EnforceIPBinding               bool          `mapstructure:"enforce_ip_binding"`
	EnforcePKCEForConfidential     bool          `mapstructure:"enforce_pkce_for_confidential"`
	MFAAccountMaxAttempts          int           `mapstructure:"mfa_account_max_attempts"`
	MFAAccountRateLimitWindow      time.Duration `mapstructure:"mfa_account_rate_limit_window"`
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	ExposedHeaders   []string `mapstructure:"exposed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

type OAuthProviderConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret" json:"-"`
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

// ObservabilityConfig holds configuration for metrics and distributed tracing.
type ObservabilityConfig struct {
	MetricsEnabled bool   `mapstructure:"metrics_enabled"`
	TracingEnabled bool   `mapstructure:"tracing_enabled"`
	OTLPEndpoint   string `mapstructure:"otlp_endpoint"`
}

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
	if err := c.validateObservability(); err != nil {
		errs = append(errs, err)
	}
	if err := c.validateOAuthProviders(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (c *GoUnoConfig) validateWebServer() error {
	if c.WebServerConfig.Port < 1 || c.WebServerConfig.Port > 65535 {
		return fmt.Errorf("web_server: port must be a valid port number (1-65535), got %d", c.WebServerConfig.Port)
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
	if c.WebServerConfig.Production && len(c.WebServerConfig.TrustedProxies) == 0 {
		return fmt.Errorf("web_server: trusted_proxies must not be empty in production (set to proxy CIDRs, e.g. [\"172.22.0.0/16\"])")
	}
	for _, proxy := range c.WebServerConfig.TrustedProxies {
		if net.ParseIP(proxy) == nil && !isValidCIDR(proxy) {
			return fmt.Errorf("web_server: trusted_proxies entry %q is not a valid IP address or CIDR notation", proxy)
		}
	}
	if c.WebServerConfig.Address != "" && net.ParseIP(c.WebServerConfig.Address) == nil {
		return fmt.Errorf("web_server: address must be a valid IP address (got %q)", c.WebServerConfig.Address)
	}
	if c.WebServerConfig.Production {
		switch c.WebServerConfig.Address {
		case "127.0.0.1", "::1":
			return fmt.Errorf("web_server: address %q is loopback-only and unreachable from other hosts in production (use 0.0.0.0 or a specific external IP)", c.WebServerConfig.Address)
		}
		if c.WebServerConfig.Debug {
			return fmt.Errorf("web_server: debug mode must not be enabled in production (set GOUNO_WEB_SERVER_DEBUG=false)")
		}
	}
	// Timeout relationship checks (Go's net/http warns if IdleTimeout < ReadTimeout)
	if c.WebServerConfig.IdleTimeout < c.WebServerConfig.ReadTimeout {
		return fmt.Errorf("web_server: idle_timeout (%v) must be >= read_timeout (%v)", c.WebServerConfig.IdleTimeout, c.WebServerConfig.ReadTimeout)
	}
	if c.WebServerConfig.ReadHeaderTimeout >= c.WebServerConfig.ReadTimeout {
		return fmt.Errorf("web_server: read_header_timeout (%v) must be < read_timeout (%v) for effective protection", c.WebServerConfig.ReadHeaderTimeout, c.WebServerConfig.ReadTimeout)
	}
	return validateRateLimits(c.WebServerConfig.RateLimits)
}

func validateRateLimits(rl RateLimitsConfig) error {
	checks := []struct {
		name  string
		value int
	}{
		{"login", rl.Login},
		{"token", rl.Token},
		{"passkey", rl.Passkey},
		{"api", rl.API},
		{"admin", rl.Admin},
		{"introspect", rl.Introspect},
		{"device_code", rl.DeviceCode},
		{"password", rl.Password},
		{"verify", rl.Verify},
		{"health", rl.Health},
	}
	for _, check := range checks {
		if check.value <= 0 {
			return fmt.Errorf("web_server: rate_limits.%s must be positive (got %d)", check.name, check.value)
		}
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
	defaultDriver := c.DatabaseConfig.GetDefaultDriver()
	if defaultDriver == nil {
		return fmt.Errorf("database: no default driver configured")
	}
	if defaultDriver.DSN == "" {
		return fmt.Errorf("database: default driver DSN is empty")
	}
	if c.WebServerConfig.Production && defaultDriver.DSN == defaultPostgresDSN {
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
		return fmt.Errorf("database: max_idle_conns (%d) must not exceed max_open_conns (%d)", c.DatabaseConfig.MaxIdleConns, c.DatabaseConfig.MaxOpenConns)
	}
	if c.DatabaseConfig.PoolStatsIntervalSec < 0 {
		return fmt.Errorf("database: pool_stats_interval_sec must not be negative (got %d)", c.DatabaseConfig.PoolStatsIntervalSec)
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
	if c.RedisConfig.DialTimeoutSeconds <= 0 {
		return fmt.Errorf("redis: dial_timeout_seconds must be positive (got %d)", c.RedisConfig.DialTimeoutSeconds)
	}
	if c.RedisConfig.ReadTimeoutSeconds <= 0 {
		return fmt.Errorf("redis: read_timeout_seconds must be positive (got %d)", c.RedisConfig.ReadTimeoutSeconds)
	}
	if c.RedisConfig.WriteTimeoutSeconds <= 0 {
		return fmt.Errorf("redis: write_timeout_seconds must be positive (got %d)", c.RedisConfig.WriteTimeoutSeconds)
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
	if strings.HasSuffix(c.AuthConfig.Issuer, "/") {
		return fmt.Errorf("auth: issuer must not have a trailing slash (got %q)", c.AuthConfig.Issuer)
	}
	if c.WebServerConfig.Production {
		if issuerURL.Scheme != "https" {
			return fmt.Errorf("auth: issuer must use https in production")
		}
		switch issuerURL.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return fmt.Errorf("auth: issuer must not point to localhost in production")
		}
	}
	if err := c.validateTOTPKey(); err != nil {
		return err
	}
	if err := c.validateAuthDurations(); err != nil {
		return err
	}
	if err := c.validatePrivateKeyPath(); err != nil {
		return err
	}
	if c.AuthConfig.MaxSessions <= 0 {
		return fmt.Errorf("auth: max_sessions must be positive")
	}
	if c.AuthConfig.RSAKeyBits != 0 && c.AuthConfig.RSAKeyBits < 2048 {
		return fmt.Errorf("auth: rsa_key_bits must be 0 (use default) or at least 2048 (got %d)", c.AuthConfig.RSAKeyBits)
	}
	if c.AuthConfig.MFAAccountMaxAttempts < 0 {
		return fmt.Errorf("auth: mfa_account_max_attempts must not be negative (got %d)", c.AuthConfig.MFAAccountMaxAttempts)
	}
	if c.WebServerConfig.Production && c.AuthConfig.VerifyHashPepper == "" {
		return fmt.Errorf("auth: verify_hash_pepper is required in production (env GOUNO_AUTH_VERIFY_HASH_PEPPER)")
	}
	return c.validateWebAuthn()
}

func (c *GoUnoConfig) validateTOTPKey() error {
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
	return nil
}

func (c *GoUnoConfig) validateAuthDurations() error {
	positive := []struct {
		name  string
		value time.Duration
	}{
		{"access_token_expiry", c.AuthConfig.AccessTokenExpiry},
		{"refresh_token_expiry", c.AuthConfig.RefreshTokenExpiry},
		{"id_token_expiry", c.AuthConfig.IDTokenExpiry},
		{"session_ttl", c.AuthConfig.SessionTTL},
		{"authorization_code_expiry", c.AuthConfig.AuthorizationCodeExpiry},
		{"device_code_expiry", c.AuthConfig.DeviceCodeExpiry},
		{"device_code_interval", c.AuthConfig.DeviceCodeInterval},
		{"login_rate_limit_window", c.AuthConfig.LoginRateLimitWindow},
		{"mfa_account_rate_limit_window", c.AuthConfig.MFAAccountRateLimitWindow},
	}
	for _, check := range positive {
		if check.value <= 0 {
			return fmt.Errorf("auth: %s must be positive", check.name)
		}
	}
	if c.AuthConfig.MaxSessionAge < 0 {
		return fmt.Errorf("auth: max_session_age must not be negative (got %s)", c.AuthConfig.MaxSessionAge)
	}
	if c.AuthConfig.MaxSessionAge > 0 && c.AuthConfig.MaxSessionAge < c.AuthConfig.SessionTTL {
		return fmt.Errorf("auth: max_session_age (%s) must not be shorter than session_ttl (%s)", c.AuthConfig.MaxSessionAge, c.AuthConfig.SessionTTL)
	}
	negativeChecks := []struct {
		name  string
		value time.Duration
	}{
		{"mfa_verification_ttl", c.AuthConfig.MFAVerificationTTL},
		{"password_reset_token_ttl", c.AuthConfig.PasswordResetTokenTTL},
		{"password_reset_cooldown_ttl", c.AuthConfig.PasswordResetCooldownTTL},
		{"verify_code_ttl", c.AuthConfig.VerifyCodeTTL},
		{"verify_cooldown_ttl", c.AuthConfig.VerifyCooldownTTL},
		{"challenge_ttl", c.AuthConfig.ChallengeTTL},
		{"password_reset_wait_timeout", c.AuthConfig.PasswordResetWaitTimeout},
	}
	for _, check := range negativeChecks {
		if check.value < 0 {
			return fmt.Errorf("auth: %s must not be negative (got %s)", check.name, check.value)
		}
	}
	// Non-negative checks: 0 means "use service-level default", negative is invalid.
	intChecks := []struct {
		name  string
		value int
	}{
		{"login_max_attempts", c.AuthConfig.LoginMaxAttempts},
		{"login_max_attempts_per_ip", c.AuthConfig.LoginMaxAttemptsPerIP},
		{"password_reset_max_attempts", c.AuthConfig.PasswordResetMaxAttempts},
		{"verify_code_max_attempts", c.AuthConfig.VerifyCodeMaxAttempts},
		{"backup_code_count", c.AuthConfig.BackupCodeCount},
		{"backup_code_length", c.AuthConfig.BackupCodeLength},
	}
	for _, check := range intChecks {
		if check.value < 0 {
			return fmt.Errorf("auth: %s must not be negative (got %d)", check.name, check.value)
		}
	}
	// Upper-bound checks for backup code parameters — service-layer defaults cap at these values;
	// explicitly reject higher values to avoid silent clamping confusion.
	if c.AuthConfig.BackupCodeCount > 0 && c.AuthConfig.BackupCodeCount > 20 {
		return fmt.Errorf("auth: backup_code_count must not exceed 20 (got %d)", c.AuthConfig.BackupCodeCount)
	}
	if c.AuthConfig.BackupCodeLength > 0 && c.AuthConfig.BackupCodeLength > 12 {
		return fmt.Errorf("auth: backup_code_length must not exceed 12 (got %d)", c.AuthConfig.BackupCodeLength)
	}
	// Validate login_ip_allowlist entries are valid IP addresses or CIDR ranges.
	for _, entry := range c.AuthConfig.LoginIPAllowlist {
		if net.ParseIP(entry) == nil && !isValidCIDR(entry) {
			return fmt.Errorf("auth: login_ip_allowlist entry %q is not a valid IP address or CIDR notation", entry)
		}
	}
	// password_reset_revoke_concurrency must be strictly positive (used as semaphore capacity).
	if c.AuthConfig.PasswordResetRevokeConcurrency <= 0 {
		return fmt.Errorf("auth: password_reset_revoke_concurrency must be positive (got %d)", c.AuthConfig.PasswordResetRevokeConcurrency)
	}
	return nil
}

func (c *GoUnoConfig) validatePrivateKeyPath() error {
	if c.AuthConfig.PrivateKeyPath == "" {
		if c.WebServerConfig.Production && c.AuthConfig.KeyID == "" {
			return fmt.Errorf("auth: key_id is required in production mode")
		}
		return nil
	}
	stat, err := os.Stat(c.AuthConfig.PrivateKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			if c.WebServerConfig.Production {
				return fmt.Errorf("auth: private_key_path file does not exist: %s", c.AuthConfig.PrivateKeyPath)
			}
			fmt.Fprintf(os.Stderr, "[GOSSO] Warning: auth: private_key_path file does not exist: %s (an ephemeral key will be generated on each restart)\n", c.AuthConfig.PrivateKeyPath)
		} else {
			return fmt.Errorf("auth: cannot access private_key_path: %w", err)
		}
	} else if stat.IsDir() {
		return fmt.Errorf("auth: private_key_path is a directory, not a file: %s", c.AuthConfig.PrivateKeyPath)
	}
	if c.AuthConfig.KeyID == "" {
		return fmt.Errorf("auth: key_id is required when private_key_path is set")
	}
	return nil
}

func (c *GoUnoConfig) validateWebAuthn() error {
	if c.AuthConfig.WebAuthnRPID == "" {
		return nil
	}
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
	if origin.Scheme == "http" && origin.Hostname() != "localhost" && origin.Hostname() != "127.0.0.1" && origin.Hostname() != "::1" {
		return fmt.Errorf("auth: webauthn_rp_origin with http scheme is only allowed for localhost, 127.0.0.1, or ::1")
	}
	if origin.Path != "" && origin.Path != "/" {
		return fmt.Errorf("auth: webauthn_rp_origin must not contain a path component (got %q)", origin.Path)
	}
	if origin.Fragment != "" {
		return fmt.Errorf("auth: webauthn_rp_origin must not contain a fragment")
	}
	return nil
}

func (c *GoUnoConfig) validateSMTP() error {
	if c.SMTPConfig.Host == "" {
		return nil
	}
	if c.SMTPConfig.Port <= 0 {
		return fmt.Errorf("smtp: port must be positive when host is configured (check GOUNO_SMTP_PORT environment variable)")
	}
	if c.SMTPConfig.From == "" {
		return fmt.Errorf("smtp: from address is required when host is configured")
	}
	switch c.SMTPConfig.TLSPolicy {
	case "", "opportunistic", "mandatory", "notls":
	default:
		return fmt.Errorf("smtp: tls_policy must be one of: opportunistic, mandatory, notls (got %q)", c.SMTPConfig.TLSPolicy)
	}
	if c.WebServerConfig.Production && c.SMTPConfig.TLSPolicy == "notls" {
		return fmt.Errorf("smtp: tls_policy 'notls' is not allowed in production (set GOUNO_SMTP_TLS_POLICY=mandatory)")
	}
	if c.AuthConfig.PasswordResetBaseURL == "" {
		return fmt.Errorf("auth: password_reset_base_url is required when SMTP is configured")
	}
	resetURL, err := url.Parse(c.AuthConfig.PasswordResetBaseURL)
	if err != nil || (resetURL.Scheme != "http" && resetURL.Scheme != "https") {
		return fmt.Errorf("auth: password_reset_base_url must be a valid URL with http or https scheme")
	}
	if c.WebServerConfig.Production && resetURL.Scheme != "https" {
		return fmt.Errorf("auth: password_reset_base_url must use https in production mode")
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
	if c.WebServerConfig.Production && len(c.CORSConfig.AllowedOrigins) == 0 {
		return fmt.Errorf("cors: allowed_origins is required in production mode")
	}
	for _, origin := range c.CORSConfig.AllowedOrigins {
		if err := validateCORSOrigin(origin); err != nil {
			return err
		}
	}
	return nil
}

func validateCORSOrigin(origin string) error {
	if origin == "*" {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("cors: allowed_origins contains invalid origin %q (must be a full URL with scheme and host, or \"*\")", origin)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("cors: allowed_origins contains invalid origin %q (origins must not include path, query, or fragment)", origin)
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

// isValidCIDR checks whether s is a valid CIDR notation (e.g. "10.0.0.0/8").
func isValidCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func (c *GoUnoConfig) validateObservability() error {
	var errs []error
	if c.Observability.TracingEnabled && c.Observability.OTLPEndpoint == "" {
		errs = append(errs, fmt.Errorf("observability: otlp_endpoint is required when tracing_enabled is true"))
	}
	if c.Observability.OTLPEndpoint != "" {
		u, err := url.Parse(c.Observability.OTLPEndpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, fmt.Errorf("observability: otlp_endpoint must be a valid URL with http or https scheme"))
		}
	}
	return errors.Join(errs...)
}
