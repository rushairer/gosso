package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rushairer/gosso/config"
	"github.com/rushairer/gosso/deploy"
)

func findConfigDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "config"
	}
	for {
		configDir := filepath.Join(dir, "config")
		if _, err := os.Stat(filepath.Join(configDir, "development.yaml")); err == nil {
			return configDir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "config"
}

func parsePostgresDSN(dsn string) (user, password, host string, port int, database string) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err == nil {
			user = u.User.Username()
			password, _ = u.User.Password()
			host = u.Hostname()
			port, _ = strconv.Atoi(u.Port())
			database = strings.TrimPrefix(u.Path, "/")
			return
		}
	}

	// host=x user=x password=x dbname=x port=x ...
	parts := strings.Fields(dsn)
	for _, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			key, value := kv[0], kv[1]
			switch key {
			case "user":
				user = value
			case "password":
				password = value
			case "host":
				host = value
			case "port":
				port, _ = strconv.Atoi(value)
			case "dbname":
				database = value
			}
		}
	}
	return
}

func parseRedisDSN(dsn string) (host string, port int, password string, database int) {
	// Supports multiple Redis DSN formats:
	// redis://[:password@]host[:port][/database]
	// redis://:password@host:port/database
	// host:port
	// localhost:6379

	// Set default values
	host = "localhost"
	port = 6379
	database = 0

	if dsn == "" {
		return
	}

	if strings.HasPrefix(dsn, "redis://") || strings.HasPrefix(dsn, "rediss://") {
		u, err := url.Parse(dsn)
		if err == nil {
			host = u.Hostname()
			if parsedPort, convErr := strconv.Atoi(u.Port()); convErr == nil {
				port = parsedPort
			}
			password, _ = u.User.Password()
			if dbPath := strings.TrimPrefix(u.Path, "/"); dbPath != "" {
				database, _ = strconv.Atoi(dbPath)
			}
			return
		}
	}

	// Simple host:port format (e.g. localhost:6379)
	if strings.Contains(dsn, ":") {
		parts := strings.SplitN(dsn, ":", 2)
		if len(parts) == 2 {
			host = parts[0]
			port, _ = strconv.Atoi(parts[1])
		}
	} else if dsn != "" {
		host = dsn
	}

	return
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func exportString(name, value string) {
	fmt.Printf("export %s=%s\n", name, shellQuote(value))
}

func exportInt(name string, value int) {
	exportString(name, strconv.Itoa(value))
}

func exportBool(name string, value bool) {
	exportString(name, strconv.FormatBool(value))
}

func splitHostPortFallback(host string, fallbackPort int) (string, int) {
	parsedHost, parsedPort, err := net.SplitHostPort(host)
	if err != nil {
		return host, fallbackPort
	}
	port, err := strconv.Atoi(parsedPort)
	if err != nil {
		return parsedHost, fallbackPort
	}
	return parsedHost, port
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("❌ Usage: %s <environment>", os.Args[0])
	}

	env := os.Args[1]

	// Initialize deployment configuration
	if err := deploy.InitDeployConfig("deploy"); err != nil {
		log.Fatalf("❌ Failed to initialize deployment configuration: %v", err)
	}

	// Load configuration using the standard config manager
	configDir := findConfigDir()
	configManager, err := config.NewConfigManager(nil, configDir, env)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}
	cfg := configManager.Config()

	// Get environment configuration
	envConfig, exists := deploy.GetEnvironment(env)
	if !exists {
		log.Fatalf("❌ Environment configuration not found: %s", env)
	}

	// Parse PostgreSQL configuration
	pgDriver := cfg.DatabaseConfig.GetDriver("postgres")
	if pgDriver == nil {
		log.Fatalf("❌ postgres database configuration not found")
	}

	pgUser, pgPassword, pgHost, _, pgDatabase := parsePostgresDSN(pgDriver.DSN)

	// Parse Redis configuration
	redisHost, _, redisPassword, redisDatabase := parseRedisDSN(cfg.RedisConfig.DSN)

	// Output application configuration
	exportInt("APP_PORT", envConfig.App.Port)
	exportInt("APP_EXTERNAL_PORT", envConfig.App.ExternalPort)
	exportString("GIN_MODE", envConfig.App.GinMode)
	exportBool("DEBUG", envConfig.App.Debug)

	// Output PostgreSQL configuration (prioritize environment config, fallback to parsed config)
	if envConfig.Postgres.Database != "" {
		exportString("POSTGRES_DB", envConfig.Postgres.Database)
	} else {
		exportString("POSTGRES_DB", pgDatabase)
	}

	if envConfig.Postgres.User != "" {
		exportString("POSTGRES_USER", envConfig.Postgres.User)
	} else {
		exportString("POSTGRES_USER", pgUser)
	}

	if envConfig.Postgres.Password != "" {
		exportString("POSTGRES_PASSWORD", envConfig.Postgres.Password)
	} else {
		exportString("POSTGRES_PASSWORD", pgPassword)
	}

	pgHost, pgPort := splitHostPortFallback(pgHost, envConfig.Postgres.Port)
	if pgHost == "" {
		pgHost = "postgres"
	}
	exportString("POSTGRES_HOST", pgHost)
	exportInt("POSTGRES_PORT", pgPort)
	exportInt("POSTGRES_EXTERNAL_PORT", envConfig.Postgres.ExternalPort)

	// Output Redis configuration
	redisHost, redisPort := splitHostPortFallback(redisHost, envConfig.Redis.Port)
	exportString("REDIS_HOST", redisHost)
	exportInt("REDIS_PORT", redisPort)
	exportInt("REDIS_EXTERNAL_PORT", envConfig.Redis.ExternalPort)
	if redisPassword != "" {
		exportString("REDIS_PASSWORD", redisPassword)
	}
	// Prioritize using the database number from the environment configuration
	if envConfig.Redis.Database != 0 {
		exportInt("REDIS_DATABASE", envConfig.Redis.Database)
	} else {
		exportInt("REDIS_DATABASE", redisDatabase)
	}

	// Output SMTP configuration
	exportString("SMTP_HOST", envConfig.SMTP.Host)
	exportInt("SMTP_PORT", envConfig.SMTP.Port)
	exportInt("SMTP_EXTERNAL_PORT", envConfig.SMTP.ExternalPort)
	exportString("SMTP_USERNAME", cfg.SMTPConfig.Username)
	exportString("SMTP_PASSWORD", cfg.SMTPConfig.Password)
	exportString("SMTP_FROM", cfg.SMTPConfig.From)

	// Output Mailpit configuration
	exportInt("MAILPIT_WEB_PORT", envConfig.Mailpit.WebPort)
	exportInt("MAILPIT_WEB_EXTERNAL_PORT", envConfig.Mailpit.WebExternalPort)

	// Output Nginx configuration (only production environment)
	if envConfig.Nginx.HTTPPort != 0 {
		exportInt("NGINX_HTTP_PORT", envConfig.Nginx.HTTPPort)
		exportInt("NGINX_HTTPS_PORT", envConfig.Nginx.HTTPSPort)
	}

	// Output network configuration
	exportString("NETWORK_NAME", envConfig.Network.Name)
	exportString("NETWORK_SUBNET", envConfig.Network.Subnet)

	// Output configuration information to stderr
	fmt.Fprintf(os.Stderr, "✅ %s environment configuration parsed:\n", strings.ToUpper(env))
	fmt.Fprintf(os.Stderr, "  🌐 App: %d -> %d (%s)\n", envConfig.App.ExternalPort, envConfig.App.Port, envConfig.App.GinMode)
	fmt.Fprintf(os.Stderr, "  🐘 PostgreSQL: %s:%d -> %d (DB: %s)\n", pgHost, envConfig.Postgres.ExternalPort, envConfig.Postgres.Port, envConfig.Postgres.Database)
	fmt.Fprintf(os.Stderr, "  🔴 Redis: %s:%d -> %d (DB: %d)\n", redisHost, envConfig.Redis.ExternalPort, envConfig.Redis.Port, envConfig.Redis.Database)
	fmt.Fprintf(os.Stderr, "  📧 SMTP: %s:%d -> %d\n", envConfig.SMTP.Host, envConfig.SMTP.ExternalPort, envConfig.SMTP.Port)
	fmt.Fprintf(os.Stderr, "  🌐 Mailpit Web: %d -> %d\n", envConfig.Mailpit.WebExternalPort, envConfig.Mailpit.WebPort)
	if envConfig.Nginx.HTTPPort != 0 {
		fmt.Fprintf(os.Stderr, "  🌐 Nginx: %d (HTTP), %d (HTTPS)\n", envConfig.Nginx.HTTPPort, envConfig.Nginx.HTTPSPort)
	}
	if redisPassword != "" {
		fmt.Fprintf(os.Stderr, "  🔐 Redis Password: ***\n")
	}
}
