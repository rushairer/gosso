package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfig returns a GoUnoConfig that passes Validate().
// It uses fake credentials only — nothing real or reusable.
func validConfig() GoUnoConfig {
	return GoUnoConfig{
		WebServerConfig: WebServerConfig{
			Port:              8080,
			MaxBodySize:       10 * 1024 * 1024,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
			RequestTimeout:    30 * time.Second,
			ShutdownTimeout:   30 * time.Second,
			TrustedProxies:    []string{"172.22.0.0/16"},
			RateLimits: RateLimitsConfig{
				Login:      5,
				Token:      10,
				Passkey:    10,
				API:        60,
				Admin:      30,
				Introspect: 20,
				DeviceCode: 10,
				Password:   3,
				Verify:     3,
				Health:     60,
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
			DSN:                 "redis://redis.example.com:6379/0",
			MaxActiveConns:      10,
			PoolTimeoutSeconds:  5,
			DialTimeoutSeconds:  5,
			ReadTimeoutSeconds:  3,
			WriteTimeoutSeconds: 3,
		},
		AuthConfig: AuthConfig{
			Issuer:                         "https://sso.example.com",
			AccessTokenExpiry:              15 * time.Minute,
			RefreshTokenExpiry:             168 * time.Hour,
			IDTokenExpiry:                  15 * time.Minute,
			SessionTTL:                     24 * time.Hour,
			MaxSessions:                    5,
			AuthorizationCodeExpiry:        5 * time.Minute,
			DeviceCodeExpiry:               10 * time.Minute,
			DeviceCodeInterval:             5 * time.Second,
			TOTPEncryptionKey:              "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", // 32 bytes, fake, differs from dev default
			VerifyHashPepper:               "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			LoginRateLimitWindow:           15 * time.Minute,
			LoginMaxAttempts:               5,
			LoginMaxAttemptsPerIP:          30,
			PasswordResetMaxAttempts:       3,
			VerifyCodeMaxAttempts:          5,
			MFAAccountRateLimitWindow:      15 * time.Minute,
			PasswordResetRevokeConcurrency: 5,
		},
		CORSConfig: CORSConfig{
			AllowedOrigins: []string{"https://app.example.com"},
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

func TestConfigManager_ProductionConfigLoadsFromEnv(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "private.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("placeholder"), 0o600))

	t.Setenv("GOUNO_DATABASE_DRIVERS_POSTGRES_DSN", "host=postgres user=gosso password=strong dbname=gosso port=5432 sslmode=require")
	t.Setenv("GOUNO_REDIS_DSN", "redis://:strong@redis:6379/0")
	t.Setenv("GOUNO_AUTH_ISSUER", "https://sso.example.com")
	t.Setenv("GOUNO_AUTH_PRIVATE_KEY_PATH", keyPath)
	t.Setenv("GOUNO_AUTH_KEY_ID", "test-key-id")
	t.Setenv("GOUNO_AUTH_PASSWORD_RESET_BASE_URL", "https://sso.example.com/reset-password")
	t.Setenv("GOUNO_AUTH_TOTP_ENCRYPTION_KEY", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	t.Setenv("GOUNO_AUTH_VERIFY_HASH_PEPPER", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	t.Setenv("GOUNO_CORS_ALLOWED_ORIGINS", "https://sso.example.com")

	cm, err := NewConfigManager(nil, "../config", "production")
	require.NoError(t, err)

	cfg := cm.Config()
	assert.Equal(t, "https://sso.example.com", cfg.AuthConfig.Issuer)
	assert.Equal(t, keyPath, cfg.AuthConfig.PrivateKeyPath)
	assert.Equal(t, "https://sso.example.com/reset-password", cfg.AuthConfig.PasswordResetBaseURL)
	assert.Equal(t, "redis://:strong@redis:6379/0", cfg.RedisConfig.DSN)
	assert.Equal(t, "host=postgres user=gosso password=strong dbname=gosso port=5432 sslmode=require", cfg.DatabaseConfig.GetDefaultDriver().DSN)
	assert.Equal(t, []string{"https://sso.example.com"}, cfg.CORSConfig.AllowedOrigins)
}

func TestLoadEnvironmentSecretFilePrefersConfiguredFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redis_dsn")
	require.NoError(t, os.WriteFile(path, []byte(" redis://:from-file@redis:6379/0\n"), 0o600))
	t.Setenv("GOUNO_REDIS_DSN_FILE", path)
	t.Setenv("GOUNO_REDIS_DSN", "redis://:from-env@redis:6379/0")

	require.NoError(t, loadEnvironmentSecretFile("GOUNO_REDIS_DSN", "GOUNO_REDIS_DSN_FILE"))
	assert.Equal(t, "redis://:from-file@redis:6379/0", os.Getenv("GOUNO_REDIS_DSN"))
}

func TestLoadEnvironmentSecretFileFailsClosed(t *testing.T) {
	t.Run("unset file variable leaves runtime value unchanged", func(t *testing.T) {
		t.Setenv("TEST_SECRET_FILE", "")
		t.Setenv("TEST_SECRET", "existing")
		require.NoError(t, loadEnvironmentSecretFile("TEST_SECRET", "TEST_SECRET_FILE"))
		assert.Equal(t, "existing", os.Getenv("TEST_SECRET"))
	})

	t.Run("unreadable configured file is rejected", func(t *testing.T) {
		t.Setenv("TEST_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
		require.ErrorContains(t, loadEnvironmentSecretFile("TEST_SECRET", "TEST_SECRET_FILE"), "read TEST_SECRET_FILE")
	})

	t.Run("empty configured file is rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty")
		require.NoError(t, os.WriteFile(path, []byte(" \n"), 0o600))
		t.Setenv("TEST_SECRET_FILE", path)
		require.ErrorContains(t, loadEnvironmentSecretFile("TEST_SECRET", "TEST_SECRET_FILE"), "TEST_SECRET_FILE is empty")
	})
}

func TestConfigManagerBindsSupportedCommandFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "gosso"}
	cmd.Flags().String("address", "", "")
	cmd.Flags().Int("port", 0, "")
	cmd.Flags().Bool("debug", false, "")
	cmd.Flags().String("env", "", "")
	require.NoError(t, cmd.Flags().Set("address", "127.0.0.1"))
	require.NoError(t, cmd.Flags().Set("port", "9090"))

	cm, err := NewConfigManager(cmd, "../config", "test")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", cm.Config().WebServerConfig.Address)
	assert.Equal(t, 9090, cm.Config().WebServerConfig.Port)
}

func TestConfigManagerParsesEnvSlice(t *testing.T) {
	t.Setenv("GOUNO_AUTH_BACKCHANNEL_ALLOWED_CIDRS", "172.21.0.0/16,10.0.0.0/8")
	cm, err := NewConfigManager(nil, "../config", "test")
	require.NoError(t, err)
	assert.Equal(t, []string{"172.21.0.0/16", "10.0.0.0/8"}, cm.Config().AuthConfig.BackchannelAllowedCIDRs)
}

func TestConfigValidationHelperFailures(t *testing.T) {
	tests := []struct {
		name     string
		validate func(*GoUnoConfig) error
		mutate   func(*GoUnoConfig)
		wantErr  string
	}{
		{
			name:     "web server rejects invalid trusted proxy",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.TrustedProxies = []string{"not-a-proxy"} },
			wantErr:  "trusted_proxies entry",
		},
		{
			name:     "web server rejects invalid port",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.Port = 0 },
			wantErr:  "port must be a valid",
		},
		{
			name:     "web server requires positive body limit",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.MaxBodySize = 0 },
			wantErr:  "max_body_size",
		},
		{
			name:     "web server requires positive read timeout",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.ReadTimeout = 0 },
			wantErr:  "read_timeout",
		},
		{
			name:     "web server requires positive write timeout",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.WriteTimeout = 0 },
			wantErr:  "write_timeout",
		},
		{
			name:     "web server requires positive header timeout",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.ReadHeaderTimeout = 0 },
			wantErr:  "read_header_timeout",
		},
		{
			name:     "web server requires positive idle timeout",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.IdleTimeout = 0 },
			wantErr:  "idle_timeout",
		},
		{
			name:     "web server requires positive request timeout",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.RequestTimeout = 0 },
			wantErr:  "request_timeout",
		},
		{
			name:     "web server requires positive shutdown timeout",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.ShutdownTimeout = 0 },
			wantErr:  "shutdown_timeout",
		},
		{
			name:     "web server production rejects debug mode",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.Production, c.WebServerConfig.Debug = true, true },
			wantErr:  "debug mode must not be enabled",
		},
		{
			name:     "web server production requires trusted proxies",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.Production, c.WebServerConfig.TrustedProxies = true, nil },
			wantErr:  "trusted_proxies must not be empty",
		},
		{
			name:     "web server production rejects loopback binding",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.Production, c.WebServerConfig.Address = true, "127.0.0.1" },
			wantErr:  "loopback-only",
		},
		{
			name:     "web server enforces timeout ordering",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.IdleTimeout = c.WebServerConfig.ReadTimeout - time.Second },
			wantErr:  "idle_timeout",
		},
		{
			name:     "web server enforces header timeout ordering",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.ReadHeaderTimeout = c.WebServerConfig.ReadTimeout },
			wantErr:  "read_header_timeout",
		},
		{
			name:     "web server rejects invalid address",
			validate: func(c *GoUnoConfig) error { return c.validateWebServer() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.Address = "invalid-address" },
			wantErr:  "address must be a valid IP address",
		},
		{
			name:     "log rejects invalid format",
			validate: func(c *GoUnoConfig) error { return c.validateLog() },
			mutate:   func(c *GoUnoConfig) { c.LogConfig.Format = "xml" },
			wantErr:  "format must be",
		},
		{
			name:     "log rejects invalid level",
			validate: func(c *GoUnoConfig) error { return c.validateLog() },
			mutate:   func(c *GoUnoConfig) { c.LogConfig.Level = 6 },
			wantErr:  "level must be",
		},
		{
			name:     "database rejects negative pool stats interval",
			validate: func(c *GoUnoConfig) error { return c.validateDatabase() },
			mutate:   func(c *GoUnoConfig) { c.DatabaseConfig.PoolStatsIntervalSec = -1 },
			wantErr:  "pool_stats_interval_sec",
		},
		{
			name:     "cors rejects negative max age",
			validate: func(c *GoUnoConfig) error { return c.validateCORS() },
			mutate:   func(c *GoUnoConfig) { c.CORSConfig.MaxAge = -1 },
			wantErr:  "max_age must not be negative",
		},
		{
			name:     "cors rejects wildcard credentials",
			validate: func(c *GoUnoConfig) error { return c.validateCORS() },
			mutate: func(c *GoUnoConfig) {
				c.CORSConfig.AllowCredentials, c.CORSConfig.AllowedOrigins = true, []string{"*"}
			},
			wantErr: "allow_credentials cannot be used",
		},
		{
			name:     "cors production requires origins",
			validate: func(c *GoUnoConfig) error { return c.validateCORS() },
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production, c.CORSConfig.AllowedOrigins = true, nil
			},
			wantErr: "allowed_origins is required",
		},
		{
			name:     "private key requires key ID in production",
			validate: func(c *GoUnoConfig) error { return c.validatePrivateKeyPath() },
			mutate:   func(c *GoUnoConfig) { c.WebServerConfig.Production = true },
			wantErr:  "key_id is required",
		},
		{
			name:     "private key rejects a configured directory",
			validate: func(c *GoUnoConfig) error { return c.validatePrivateKeyPath() },
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.PrivateKeyPath, c.AuthConfig.KeyID = t.TempDir(), "key-id"
			},
			wantErr: "is a directory",
		},
		{
			name:     "private key production rejects a missing file",
			validate: func(c *GoUnoConfig) error { return c.validatePrivateKeyPath() },
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production = true
				c.AuthConfig.PrivateKeyPath, c.AuthConfig.KeyID = filepath.Join(t.TempDir(), "missing"), "key-id"
			},
			wantErr: "file does not exist",
		},
		{
			name:     "smtp requires a port when configured",
			validate: func(c *GoUnoConfig) error { return c.validateSMTP() },
			mutate:   func(c *GoUnoConfig) { c.SMTPConfig.Host = "smtp.example.com" },
			wantErr:  "smtp: port must be positive",
		},
		{
			name:     "smtp requires from address when configured",
			validate: func(c *GoUnoConfig) error { return c.validateSMTP() },
			mutate: func(c *GoUnoConfig) {
				c.SMTPConfig.Host, c.SMTPConfig.Port = "smtp.example.com", 587
			},
			wantErr: "smtp: from address is required",
		},
		{
			name:     "smtp rejects invalid TLS policy",
			validate: func(c *GoUnoConfig) error { return c.validateSMTP() },
			mutate: func(c *GoUnoConfig) {
				c.SMTPConfig.Host, c.SMTPConfig.Port, c.SMTPConfig.From, c.SMTPConfig.TLSPolicy = "smtp.example.com", 587, "noreply@example.com", "invalid"
			},
			wantErr: "tls_policy must be one of",
		},
		{
			name:     "webauthn requires a name when configured",
			validate: func(c *GoUnoConfig) error { return c.validateWebAuthn() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.WebAuthnRPID = "sso.example.com" },
			wantErr:  "webauthn_rp_name is required",
		},
		{
			name:     "webauthn requires an origin when configured",
			validate: func(c *GoUnoConfig) error { return c.validateWebAuthn() },
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID, c.AuthConfig.WebAuthnRPName = "sso.example.com", "GOSSO"
			},
			wantErr: "webauthn_rp_origin is required",
		},
		{
			name:     "webauthn rejects non-local HTTP origins",
			validate: func(c *GoUnoConfig) error { return c.validateWebAuthn() },
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID, c.AuthConfig.WebAuthnRPName, c.AuthConfig.WebAuthnRPOrigin = "sso.example.com", "GOSSO", "http://sso.example.com"
			},
			wantErr: "only allowed for localhost",
		},
		{
			name:     "webauthn rejects path components",
			validate: func(c *GoUnoConfig) error { return c.validateWebAuthn() },
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID, c.AuthConfig.WebAuthnRPName, c.AuthConfig.WebAuthnRPOrigin = "sso.example.com", "GOSSO", "https://sso.example.com/path"
			},
			wantErr: "must not contain a path component",
		},
		{
			name:     "webauthn rejects fragments",
			validate: func(c *GoUnoConfig) error { return c.validateWebAuthn() },
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID, c.AuthConfig.WebAuthnRPName, c.AuthConfig.WebAuthnRPOrigin = "sso.example.com", "GOSSO", "https://sso.example.com#fragment"
			},
			wantErr: "must not contain a fragment",
		},
		{
			name:     "smtp production rejects plaintext policy",
			validate: func(c *GoUnoConfig) error { return c.validateSMTP() },
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production = true
				c.SMTPConfig.Host, c.SMTPConfig.Port, c.SMTPConfig.From, c.SMTPConfig.TLSPolicy = "smtp.example.com", 587, "noreply@example.com", "notls"
			},
			wantErr: "not allowed in production",
		},
		{
			name:     "auth production requires verification pepper",
			validate: func(c *GoUnoConfig) error { return c.validateAuth() },
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production = true
				c.AuthConfig.KeyID = "key-id"
				c.AuthConfig.VerifyHashPepper = ""
			},
			wantErr: "verify_hash_pepper is required",
		},
		{
			name:     "oauth provider requires a matching secret",
			validate: func(c *GoUnoConfig) error { return c.validateOAuthProviders() },
			mutate:   func(c *GoUnoConfig) { c.OAuthProviders.Google.ClientID = "client" },
			wantErr:  "client_secret is required",
		},
		{
			name:     "oauth provider rejects invalid redirect URL",
			validate: func(c *GoUnoConfig) error { return c.validateOAuthProviders() },
			mutate: func(c *GoUnoConfig) {
				c.OAuthProviders.GitHub = OAuthProviderConfig{ClientID: "client", ClientSecret: "secret", RedirectURI: "ftp://example.com"}
			},
			wantErr: "redirect_uri must be a valid URL",
		},
		{
			name:     "observability requires endpoint for tracing",
			validate: func(c *GoUnoConfig) error { return c.validateObservability() },
			mutate:   func(c *GoUnoConfig) { c.Observability.TracingEnabled = true },
			wantErr:  "otlp_endpoint is required",
		},
		{
			name:     "observability rejects invalid endpoint",
			validate: func(c *GoUnoConfig) error { return c.validateObservability() },
			mutate:   func(c *GoUnoConfig) { c.Observability.OTLPEndpoint = "grpc://collector" },
			wantErr:  "otlp_endpoint must be a valid URL",
		},
		{
			name:     "redis rejects zero dial timeout",
			validate: func(c *GoUnoConfig) error { return c.validateRedis() },
			mutate:   func(c *GoUnoConfig) { c.RedisConfig.DialTimeoutSeconds = 0 },
			wantErr:  "dial_timeout_seconds",
		},
		{
			name:     "redis rejects zero read timeout",
			validate: func(c *GoUnoConfig) error { return c.validateRedis() },
			mutate:   func(c *GoUnoConfig) { c.RedisConfig.ReadTimeoutSeconds = 0 },
			wantErr:  "read_timeout_seconds",
		},
		{
			name:     "redis rejects zero write timeout",
			validate: func(c *GoUnoConfig) error { return c.validateRedis() },
			mutate:   func(c *GoUnoConfig) { c.RedisConfig.WriteTimeoutSeconds = 0 },
			wantErr:  "write_timeout_seconds",
		},
		{
			name:     "auth durations reject a negative maximum session age",
			validate: func(c *GoUnoConfig) error { return c.validateAuthDurations() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.MaxSessionAge = -time.Second },
			wantErr:  "max_session_age must not be negative",
		},
		{
			name:     "auth durations reject maximum session age below session TTL",
			validate: func(c *GoUnoConfig) error { return c.validateAuthDurations() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.MaxSessionAge = c.AuthConfig.SessionTTL - time.Second },
			wantErr:  "must not be shorter than session_ttl",
		},
		{
			name:     "auth durations reject excessive backup code count",
			validate: func(c *GoUnoConfig) error { return c.validateAuthDurations() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.BackupCodeCount = 21 },
			wantErr:  "backup_code_count must not exceed",
		},
		{
			name:     "auth durations reject invalid login IP allowlist entries",
			validate: func(c *GoUnoConfig) error { return c.validateAuthDurations() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.LoginIPAllowlist = []string{"invalid-ip"} },
			wantErr:  "login_ip_allowlist entry",
		},
		{
			name:     "auth durations reject invalid backchannel CIDRs",
			validate: func(c *GoUnoConfig) error { return c.validateAuthDurations() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.BackchannelAllowedCIDRs = []string{"invalid-cidr"} },
			wantErr:  "backchannel_allowed_cidrs entry",
		},
		{
			name:     "auth durations require positive revoke concurrency",
			validate: func(c *GoUnoConfig) error { return c.validateAuthDurations() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.PasswordResetRevokeConcurrency = 0 },
			wantErr:  "password_reset_revoke_concurrency must be positive",
		},
		{
			name:     "auth rejects a non HTTP issuer",
			validate: func(c *GoUnoConfig) error { return c.validateAuth() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.Issuer = "ftp://sso.example.com" },
			wantErr:  "issuer must be a valid URL",
		},
		{
			name:     "auth rejects issuer trailing slash",
			validate: func(c *GoUnoConfig) error { return c.validateAuth() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.Issuer = "https://sso.example.com/" },
			wantErr:  "must not have a trailing slash",
		},
		{
			name:     "auth production requires HTTPS issuer",
			validate: func(c *GoUnoConfig) error { return c.validateAuth() },
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production, c.AuthConfig.Issuer = true, "http://sso.example.com"
			},
			wantErr: "issuer must use https",
		},
		{
			name:     "auth production rejects localhost issuer",
			validate: func(c *GoUnoConfig) error { return c.validateAuth() },
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production, c.AuthConfig.Issuer = true, "https://localhost"
			},
			wantErr: "must not point to localhost",
		},
		{
			name:     "auth rejects undersized RSA key",
			validate: func(c *GoUnoConfig) error { return c.validateAuth() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.RSAKeyBits = 1024 },
			wantErr:  "rsa_key_bits",
		},
		{
			name:     "auth rejects negative MFA attempts",
			validate: func(c *GoUnoConfig) error { return c.validateAuth() },
			mutate:   func(c *GoUnoConfig) { c.AuthConfig.MFAAccountMaxAttempts = -1 },
			wantErr:  "mfa_account_max_attempts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			require.ErrorContains(t, tt.validate(&cfg), tt.wantErr)
		})
	}
}

func TestValidateAuthLoadsConfiguredSecretFiles(t *testing.T) {
	totpPath := filepath.Join(t.TempDir(), "totp-key")
	pepperPath := filepath.Join(t.TempDir(), "verify-pepper")
	require.NoError(t, os.WriteFile(totpPath, []byte("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n"), 0o600))
	require.NoError(t, os.WriteFile(pepperPath, []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"), 0o600))

	cfg := validConfig()
	cfg.AuthConfig.TOTPEncryptionKey = ""
	cfg.AuthConfig.TOTPEncryptionKeyPath = totpPath
	cfg.AuthConfig.VerifyHashPepper = ""
	cfg.AuthConfig.VerifyHashPepperPath = pepperPath

	require.NoError(t, cfg.validateAuth())
	assert.Equal(t, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", cfg.AuthConfig.TOTPEncryptionKey)
	assert.Equal(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", cfg.AuthConfig.VerifyHashPepper)
}

func TestValidateAggregatesIndependentValidationErrors(t *testing.T) {
	cfg := validConfig()
	cfg.LogConfig.Level = 6
	cfg.Observability.TracingEnabled = true
	cfg.OAuthProviders.Google.ClientID = "client"

	err := cfg.Validate()
	require.ErrorContains(t, err, "log: level")
	require.ErrorContains(t, err, "observability: otlp_endpoint")
	require.ErrorContains(t, err, "oauth_providers.google: client_secret")
}

func TestConfigManager_TestConfigIsValid(t *testing.T) {
	cm, err := NewConfigManager(nil, "../config", "test")
	require.NoError(t, err)

	key, err := hex.DecodeString(cm.Config().AuthConfig.TOTPEncryptionKey)
	require.NoError(t, err)
	assert.Len(t, key, 32)
}

func TestConfigManager_CSRFCookieSecureCanBeEnabledForLocalHTTPS(t *testing.T) {
	t.Setenv("GOUNO_WEB_SERVER_CSRF_COOKIE_SECURE", "true")
	t.Setenv("GOUNO_AUTH_TOTP_ENCRYPTION_KEY", "0000000000000000000000000000000000000000000000000000000000000000")

	cm, err := NewConfigManager(nil, "../config", "development")
	require.NoError(t, err)

	assert.True(t, cm.Config().WebServerConfig.CSRFCookieSecure)
	assert.False(t, cm.Config().WebServerConfig.Production)
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
				c.WebServerConfig.Production = true
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
		{
			name: "production issuer must use https",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production = true
				c.AuthConfig.Issuer = "http://sso.example.com"
			},
			wantErr: "auth: issuer must use https in production",
		},
		{
			name: "production issuer must not be localhost",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production = true
				c.AuthConfig.Issuer = "https://localhost:8080"
			},
			wantErr: "auth: issuer must not point to localhost in production",
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
			name: "zero password rate limit",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.RateLimits.Password = 0
			},
			wantErr: "rate_limits.password must be positive",
		},
		{
			name: "negative verify rate limit",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.RateLimits.Verify = -1
			},
			wantErr: "rate_limits.verify must be positive",
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

		// ── Issuer trailing slash ─────────────
		{
			name: "issuer with trailing slash",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.Issuer = "https://sso.example.com/"
			},
			wantErr: "auth: issuer must not have a trailing slash",
		},

		// ── KeyID required ────────────────────
		{
			name: "missing key_id when private_key_path set",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.PrivateKeyPath = "/path/to/key.pem"
				c.AuthConfig.KeyID = ""
			},
			wantErr: "auth: key_id is required when private_key_path is set",
		},
		{
			name: "missing key_id in production without private_key_path",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Production = true
				c.AuthConfig.PrivateKeyPath = ""
				c.AuthConfig.KeyID = ""
			},
			wantErr: "auth: key_id is required in production mode",
		},

		// ── Address validation ────────────────
		{
			name: "invalid web_server address",
			mutate: func(c *GoUnoConfig) {
				c.WebServerConfig.Address = "not-an-ip"
			},
			wantErr: "web_server: address must be a valid IP address",
		},

		// ── CORS origin format ────────────────
		{
			name: "cors invalid origin format",
			mutate: func(c *GoUnoConfig) {
				c.CORSConfig.AllowedOrigins = []string{"not-a-url"}
			},
			wantErr: "cors: allowed_origins contains invalid origin",
		},

		// ── MaxSessionAge cross-validation ────
		{
			name: "max_session_age shorter than session_ttl",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.MaxSessionAge = 1 * time.Hour
				c.AuthConfig.SessionTTL = 24 * time.Hour
			},
			wantErr: "auth: max_session_age (1h0m0s) must not be shorter than session_ttl (24h0m0s)",
		},

		// ── WebAuthn IPv6 loopback (should pass) ──
		{
			name: "webauthn http origin allows IPv6 loopback",
			mutate: func(c *GoUnoConfig) {
				c.AuthConfig.WebAuthnRPID = "localhost"
				c.AuthConfig.WebAuthnRPName = "Test"
				c.AuthConfig.WebAuthnRPOrigin = "http://[::1]:3000"
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidate_DebugIssuerAllowsLocalhostHTTP(t *testing.T) {
	cfg := validConfig()
	cfg.WebServerConfig.Debug = true
	cfg.AuthConfig.Issuer = "http://localhost:8080"

	assert.NoError(t, cfg.Validate())
}

func TestValidate_AccumulatesErrorsAcrossSections(t *testing.T) {
	cfg := validConfig()
	// Introduce errors in multiple sections simultaneously
	cfg.DatabaseConfig.Default = "nonexistent" // database error
	cfg.RedisConfig.DSN = ""                   // redis error
	cfg.AuthConfig.TOTPEncryptionKey = ""      // auth error
	cfg.WebServerConfig.RateLimits.Login = 0   // web_server error

	err := cfg.Validate()
	require.Error(t, err)

	errMsg := err.Error()
	// All four section errors should appear in the joined error
	assert.Contains(t, errMsg, "database: no default driver configured")
	assert.Contains(t, errMsg, "redis: DSN is empty")
	assert.Contains(t, errMsg, "auth: totp_encryption_key is required")
	assert.Contains(t, errMsg, "rate_limits.login must be positive")
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
// ConfigManager.setConfig / Config
// ──────────────────────────────────────────────

func TestConfigManager_SetConfig_GetConfig(t *testing.T) {
	cm := &ConfigManager{}

	// Before setting config, Config() returns zero value
	assert.Equal(t, GoUnoConfig{}, cm.Config())

	cfg := validConfig()
	cm.config = cfg

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

	assert.Equal(t, 8080, v.GetInt("web_server.port"))
	assert.Equal(t, "0.0.0.0", v.GetString("web_server.address"))
	assert.Equal(t, int64(10*1024*1024), v.GetInt64("web_server.max_body_size"))
	assert.Equal(t, "postgres", v.GetString("database.default"))
	assert.Equal(t, "pgx", v.GetString("database.drivers.postgres.driver"))
	assert.Equal(t, 25, v.GetInt("database.max_open_conns"))
	assert.Equal(t, "15m", v.GetString("auth.access_token_expiry"))
	assert.Equal(t, "168h", v.GetString("auth.refresh_token_expiry"))
	assert.Equal(t, 0, v.GetInt("log.level"))
}

func TestValidate_LoadSecretsFromPath(t *testing.T) {
	totpFile, err := os.CreateTemp("", "totp_key_*")
	assert.NoError(t, err)
	defer os.Remove(totpFile.Name())

	pepperFile, err := os.CreateTemp("", "pepper_*")
	assert.NoError(t, err)
	defer os.Remove(pepperFile.Name())

	_, _ = totpFile.WriteString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
	_ = totpFile.Close()

	_, _ = pepperFile.WriteString("super-secret-pepper-from-file\n")
	_ = pepperFile.Close()

	cfg := validConfig()
	cfg.WebServerConfig.Production = true
	cfg.AuthConfig.Issuer = "https://sso.example.com"
	cfg.AuthConfig.KeyID = "prod-key-1"
	cfg.AuthConfig.TOTPEncryptionKey = ""
	cfg.AuthConfig.TOTPEncryptionKeyPath = totpFile.Name()
	cfg.AuthConfig.VerifyHashPepper = ""
	cfg.AuthConfig.VerifyHashPepperPath = pepperFile.Name()

	err = cfg.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", cfg.AuthConfig.TOTPEncryptionKey)
	assert.Equal(t, "super-secret-pepper-from-file", cfg.AuthConfig.VerifyHashPepper)
}
