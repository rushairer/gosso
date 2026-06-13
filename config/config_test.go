package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfig returns a GoUnoConfig that passes Validate().
// It uses fake credentials only — nothing real or reusable.
func validConfig() GoUnoConfig {
	return GoUnoConfig{
		WebServerConfig: WebServerConfig{
			Port:              "8080",
			MaxBodySize:       10 * 1024 * 1024,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
			RequestTimeout:    30 * time.Second,
			ShutdownTimeout:   30 * time.Second,
			RateLimits: RateLimitsConfig{
				Login:      5,
				Token:      10,
				Passkey:    10,
				API:        60,
				Introspect: 20,
				DeviceCode: 10,
			},
		},
		DatabaseConfig: DatabaseConfig{
			Default: "postgres",
			Drivers: map[DatabaseConfigDriverName]DatabaseConfigDriver{
				"postgres": {
					Name:   "postgres",
					Driver: "pgx",
					DSN:    "postgres://user:pass@db.example.com:5432/gosso_prod?sslmode=require",
				},
			},
			MaxOpenConns:       25,
			MaxIdleConns:       5,
			ConnMaxLifetimeSec: 300,
			ConnMaxIdleTimeSec: 180,
		},
		RedisConfig: RedisConfig{
			DSN:                "redis://redis.example.com:6379/0",
			MaxActiveConns:     10,
			PoolTimeoutSeconds: 5,
		},
		AuthConfig: AuthConfig{
			Issuer:                  "https://sso.example.com",
			AccessTokenExpiry:       15 * time.Minute,
			RefreshTokenExpiry:      168 * time.Hour,
			IDTokenExpiry:           15 * time.Minute,
			SessionTTL:              24 * time.Hour,
			MaxSessions:             5,
			AuthorizationCodeExpiry: 5 * time.Minute,
			DeviceCodeExpiry:        10 * time.Minute,
			DeviceCodeInterval:      5 * time.Second,
			TOTPEncryptionKey:       "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", // 32 bytes, fake, differs from dev default
		},
	}
}

// ──────────────────────────────────────────────
// Validate — success
// ──────────────────────────────────────────────

func TestValidate_ValidConfig(t *testing.T) {
	cfg := validConfig()
	assert.NoError(t, cfg.Validate())
}

// ──────────────────────────────────────────────
// Validate — table-driven error cases
// ──────────────────────────────────────────────

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*GoUnoConfig)
		wantErr string
	}{
		// ── Database ────────────────────────────
		{
			name: "nil default driver",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.Default = "nonexistent"
			},
			wantErr: "database: no default driver configured",
		},
		{
			name: "empty DSN",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.Drivers["postgres"] = DatabaseConfigDriver{
					Name: "postgres", Driver: "pgx", DSN: "",
				}
			},
			wantErr: "database: default driver DSN is empty",
		},
		{
			name: "default dev DSN rejected",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.Drivers["postgres"] = DatabaseConfigDriver{
					Name: "postgres", Driver: "pgx", DSN: defaultPostgresDSN,
				}
			},
			wantErr: "database: default driver DSN must be explicitly configured",
		},
		{
			name: "negative conn_max_lifetime_sec",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.ConnMaxLifetimeSec = -1
			},
			wantErr: "database: conn_max_lifetime_sec must not be negative",
		},
		{
			name: "negative conn_max_idle_time_sec",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.ConnMaxIdleTimeSec = -1
			},
			wantErr: "database: conn_max_idle_time_sec must not be negative",
		},
		{
			name: "zero max_open_conns",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.MaxOpenConns = 0
			},
			wantErr: "database: max_open_conns must be positive",
		},
		{
			name: "negative max_open_conns",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.MaxOpenConns = -1
			},
			wantErr: "database: max_open_conns must be positive",
		},
		{
			name: "max_idle_conns exceeds max_open_conns",
			mutate: func(c *GoUnoConfig) {
				c.DatabaseConfig.MaxIdleConns = 50
				c.DatabaseConfig.MaxOpenConns = 10
			},
			wantErr: "database: max_idle_conns (50) must not exceed max_open_conns (10)",
		},

		// ── Redis ───────────────────────────────
		{
			name: "empty redis DSN",
			mutate: func(c *GoUnoConfig) {
				c.RedisConfig.DSN = ""
			},
			wantErr: "redis: DSN is empty",
		},
		{
			name: "zero redis max_active_conns",
			mutate: func(c *GoUnoConfig) {
				c.RedisConfig.MaxActiveConns = 0
			},
			wantErr: "redis: max_active_conns must be positive",
		},
		{
			name: "zero redis pool_timeout_seconds",
			mutate: func(c *GoUnoConfig) {
				c.RedisConfig.PoolTimeoutSeconds = 0
			},
			wantErr: "redis: pool_timeout_seconds must be positive",
		},

		// ── Auth — issuer ───────────────────────
		{
			name: "empty issuer",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.Issuer = ""
			},
			wantErr: "auth: issuer is empty",
		},
		{
			name: "issuer not a valid URL",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.Issuer = "://bad"
			},
			wantErr: "auth: issuer must be a valid URL with http or https scheme",
		},
		{
			name: "issuer ftp scheme rejected",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.Issuer = "ftp://example.com"
			},
			wantErr: "auth: issuer must be a valid URL with http or https scheme",
		},

		// ── Auth — TOTP key ─────────────────────
		{
			name: "empty totp key",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.TOTPEncryptionKey = ""
			},
			wantErr: "auth: totp_encryption_key is required",
		},
		{
			name: "totp key not hex",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.TOTPEncryptionKey = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
			},
			wantErr: "auth: totp_encryption_key must be a valid hex string",
		},
		{
			name: "totp key wrong length",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.TOTPEncryptionKey = "abcd" // 2 bytes, need 32
			},
			wantErr: "auth: totp_encryption_key must decode to exactly 32 bytes",
		},
		{
			name: "default totp key rejected",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.TOTPEncryptionKey = defaultTOTPEncryptionKey
			},
			wantErr: "totp_encryption_key must be explicitly configured",
		},

		// ── Auth — token expiries ───────────────
		{
			name: "zero access_token_expiry",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.AccessTokenExpiry = 0
			},
			wantErr: "auth: access_token_expiry must be positive",
		},
		{
			name: "negative refresh_token_expiry",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.RefreshTokenExpiry = -1 * time.Hour
			},
			wantErr: "auth: refresh_token_expiry must be positive",
		},
		{
			name: "zero id_token_expiry",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.IDTokenExpiry = 0
			},
			wantErr: "auth: id_token_expiry must be positive",
		},
		{
			name: "zero session_ttl",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.SessionTTL = 0
			},
			wantErr: "auth: session_ttl must be positive",
		},
		{
			name: "zero authorization_code_expiry",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.AuthorizationCodeExpiry = 0
			},
			wantErr: "auth: authorization_code_expiry must be positive",
		},
		{
			name: "zero device_code_expiry",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.DeviceCodeExpiry = 0
			},
			wantErr: "auth: device_code_expiry must be positive",
		},
		{
			name: "zero device_code_interval",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.DeviceCodeInterval = 0
			},
			wantErr: "auth: device_code_interval must be positive",
		},
		{
			name: "zero max_sessions",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.MaxSessions = 0
			},
			wantErr: "auth: max_sessions must be positive",
		},

		// ── Web server — rate limits ────────────
		{
			name: "zero login rate limit",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.RateLimits.Login = 0
			},
			wantErr: "rate_limits.login must be positive",
		},
		{
			name: "negative API rate limit",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.RateLimits.API = -1
			},
			wantErr: "rate_limits.api must be positive",
		},
		{
			name: "zero max_body_size",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.MaxBodySize = 0
			},
			wantErr: "web_server: max_body_size must be positive",
		},

		// ── SMTP (host set triggers sub-validators) ──
		{
			name: "smtp port zero when host set",
			mutate: func(c *GoUnoConfig) {
				c.SMTPConfig.Host = "smtp.example.com"
				c.SMTPConfig.Port = 0
			},
			wantErr: "smtp: port must be positive when host is configured",
		},
		{
			name: "smtp from empty when host set",
			mutate: func(c *GoUnoConfig) {
				c.SMTPConfig.Host = "smtp.example.com"
				c.SMTPConfig.Port = 587
				c.SMTPConfig.From = ""
			},
			wantErr: "smtp: from address is required when host is configured",
		},
		{
			name: "smtp invalid tls_policy",
			mutate: func(c *GoUnoConfig) {
				c.SMTPConfig.Host = "smtp.example.com"
				c.SMTPConfig.Port = 587
				c.SMTPConfig.From = "no-reply@example.com"
				c.SMTPConfig.TLSPolicy = "invalid"
			},
			wantErr: "smtp: tls_policy must be one of",
		},
		{
			name: "smtp missing password_reset_base_url",
			mutate: func(c *GoUnoConfig) {
				c.SMTPConfig.Host = "smtp.example.com"
				c.SMTPConfig.Port = 587
				c.SMTPConfig.From = "no-reply@example.com"
				c.SMTPConfig.TLSPolicy = "mandatory"
			},
			wantErr: "auth: password_reset_base_url is required when SMTP is configured",
		},
		{
			name: "smtp bad password_reset_base_url scheme",
			mutate: func(c *GoUnoConfig) {
				c.SMTPConfig.Host = "smtp.example.com"
				c.SMTPConfig.Port = 587
				c.SMTPConfig.From = "no-reply@example.com"
				c.SMTPConfig.TLSPolicy = "mandatory"
				c.AuthConfig.PasswordResetBaseURL = "ftp://bad"
			},
			wantErr: "auth: password_reset_base_url must be a valid URL",
		},

		// ── WebAuthn ────────────────────────────
		{
			name: "webauthn missing rp_name",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID = "example.com"
				c.AuthConfig.WebAuthnRPName = ""
			},
			wantErr: "auth: webauthn_rp_name is required",
		},
		{
			name: "webauthn missing rp_origin",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID = "example.com"
				c.AuthConfig.WebAuthnRPName = "Example"
				c.AuthConfig.WebAuthnRPOrigin = ""
			},
			wantErr: "auth: webauthn_rp_origin is required",
		},
		{
			name: "webauthn rp_origin bad scheme",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID = "example.com"
				c.AuthConfig.WebAuthnRPName = "Example"
				c.AuthConfig.WebAuthnRPOrigin = "ftp://example.com"
			},
			wantErr: "auth: webauthn_rp_origin must be a valid URL",
		},
		{
			name: "webauthn rp_origin http non-localhost rejected",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID = "example.com"
				c.AuthConfig.WebAuthnRPName = "Example"
				c.AuthConfig.WebAuthnRPOrigin = "http://example.com"
			},
			wantErr: "auth: webauthn_rp_origin with http scheme is only allowed for localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// ──────────────────────────────────────────────
// Validate — valid configs with optional sections
// ──────────────────────────────────────────────

func TestValidate_ValidWithSMTP(t *testing.T) {
	cfg := validConfig()
	cfg.SMTPConfig = SMTPConfig{
		Host:      "smtp.example.com",
		Port:      587,
		From:      "no-reply@example.com",
		TLSPolicy: "mandatory",
	}
	cfg.AuthConfig.PasswordResetBaseURL = "https://sso.example.com/reset"
	assert.NoError(t, cfg.Validate())
}

func TestValidate_ValidWithWebAuthn(t *testing.T) {
	cfg := validConfig()
	cfg.AuthConfig.WebAuthnRPID = "example.com"
	cfg.AuthConfig.WebAuthnRPName = "Example SSO"
	cfg.AuthConfig.WebAuthnRPOrigin = "https://sso.example.com"
	assert.NoError(t, cfg.Validate())
}

func TestValidate_ValidWithWebAuthnLocalhost(t *testing.T) {
	cfg := validConfig()
	cfg.AuthConfig.WebAuthnRPID = "localhost"
	cfg.AuthConfig.WebAuthnRPName = "Dev SSO"
	cfg.AuthConfig.WebAuthnRPOrigin = "http://localhost:8080"
	assert.NoError(t, cfg.Validate())
}

// ──────────────────────────────────────────────
// DatabaseConfig.GetDriver
// ──────────────────────────────────────────────

func TestGetDriver_Existing(t *testing.T) {
	cfg := validConfig()
	d := cfg.DatabaseConfig.GetDriver("postgres")
	require.NotNil(t, d)
	assert.Equal(t, "postgres", string(d.Name))
	assert.Equal(t, "pgx", d.Driver)
	assert.NotEmpty(t, d.DSN)
}

func TestGetDriver_NonExistent(t *testing.T) {
	cfg := validConfig()
	assert.Nil(t, cfg.DatabaseConfig.GetDriver("mysql"))
}

// ──────────────────────────────────────────────
// ConfigManager.SetConfig / Config
// ──────────────────────────────────────────────

func TestConfigManager_SetConfig_GetConfig(t *testing.T) {
	cm := &ConfigManager{}

	// Before setting config, Config() returns zero value
	assert.Equal(t, GoUnoConfig{}, cm.Config())

	cfg := validConfig()
	cm.SetConfig(&cfg)

	got := cm.Config()
	assert.Equal(t, cfg.AuthConfig.Issuer, got.AuthConfig.Issuer)
	assert.Equal(t, cfg.DatabaseConfig.Default, got.DatabaseConfig.Default)
}

func TestConfigManager_Config_NilPointer(t *testing.T) {
	cm := &ConfigManager{}
	assert.Equal(t, GoUnoConfig{}, cm.Config())
}

// ──────────────────────────────────────────────
// setConfigDefaults (via Viper)
// ──────────────────────────────────────────────

func TestSetConfigDefaults(t *testing.T) {
	cm := &ConfigManager{}
	v := viper.New()
	cm.setConfigDefaults(v)

	assert.Equal(t, "8080", v.GetString("web_server.port"))
	assert.Equal(t, "0.0.0.0", v.GetString("web_server.address"))
	assert.Equal(t, int64(10*1024*1024), v.GetInt64("web_server.max_body_size"))
	assert.Equal(t, "postgres", v.GetString("database.default"))
	assert.Equal(t, "pgx", v.GetString("database.drivers.postgres.driver"))
	assert.Equal(t, 25, v.GetInt("database.max_open_conns"))
	assert.Equal(t, "15m", v.GetString("auth.access_token_expiry"))
	assert.Equal(t, "168h", v.GetString("auth.refresh_token_expiry"))
	assert.Equal(t, 0, v.GetInt("log.level"))
}
