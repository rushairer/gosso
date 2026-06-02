package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	// Reference the project's config package
	"github.com/rushairer/gosso/deploy" // Reference the project's deploy package
	"github.com/rushairer/gosso/tests"
)

func parsePostgresDSN(dsn string) (user, password, host string, port int, database string) {
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

	// Handle redis:// protocol
	if strings.HasPrefix(dsn, "redis://") {
		dsn = strings.TrimPrefix(dsn, "redis://")

		// Check if there is a password
		if strings.Contains(dsn, "@") {
			parts := strings.SplitN(dsn, "@", 2)
			if len(parts) == 2 {
				// Extract the password part
				authPart := parts[0]
				if strings.HasPrefix(authPart, ":") {
					password = strings.TrimPrefix(authPart, ":")
				}
				dsn = parts[1]
			}
		}

		// Check if there is a database number
		if strings.Contains(dsn, "/") {
			parts := strings.SplitN(dsn, "/", 2)
			if len(parts) == 2 {
				database, _ = strconv.Atoi(parts[1])
				dsn = parts[0]
			}
		}

		// Parse host:port
		if strings.Contains(dsn, ":") {
			parts := strings.SplitN(dsn, ":", 2)
			if len(parts) == 2 {
				host = parts[0]
				port, _ = strconv.Atoi(parts[1])
			}
		} else if dsn != "" {
			host = dsn
		}
	} else {
		// Simple host:port format
		if strings.Contains(dsn, ":") {
			parts := strings.SplitN(dsn, ":", 2)
			if len(parts) == 2 {
				host = parts[0]
				port, _ = strconv.Atoi(parts[1])
			}
		} else if dsn != "" {
			host = dsn
		}
	}

	return
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

	// Use GlobalConfig directly
	configManager := tests.NewTestConfigManager()
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
	fmt.Printf("export APP_PORT=%d\n", envConfig.App.Port)
	fmt.Printf("export APP_EXTERNAL_PORT=%d\n", envConfig.App.ExternalPort)
	fmt.Printf("export GIN_MODE=%s\n", envConfig.App.GinMode)
	fmt.Printf("export DEBUG=%t\n", envConfig.App.Debug)

	// Output PostgreSQL configuration (prioritize environment config, fallback to parsed config)
	if envConfig.Postgres.Database != "" {
		fmt.Printf("export POSTGRES_DB=%s\n", envConfig.Postgres.Database)
	} else {
		fmt.Printf("export POSTGRES_DB=%s\n", pgDatabase)
	}

	if envConfig.Postgres.User != "" {
		fmt.Printf("export POSTGRES_USER=%s\n", envConfig.Postgres.User)
	} else {
		fmt.Printf("export POSTGRES_USER=%s\n", pgUser)
	}

	if envConfig.Postgres.Password != "" {
		fmt.Printf("export POSTGRES_PASSWORD=%s\n", envConfig.Postgres.Password)
	} else {
		fmt.Printf("export POSTGRES_PASSWORD=%s\n", pgPassword)
	}

	fmt.Printf("export POSTGRES_HOST=%s\n", pgHost)
	fmt.Printf("export POSTGRES_PORT=%d\n", envConfig.Postgres.Port)
	fmt.Printf("export POSTGRES_EXTERNAL_PORT=%d\n", envConfig.Postgres.ExternalPort)

	// Output Redis configuration
	fmt.Printf("export REDIS_HOST=%s\n", redisHost)
	fmt.Printf("export REDIS_PORT=%d\n", envConfig.Redis.Port)
	fmt.Printf("export REDIS_EXTERNAL_PORT=%d\n", envConfig.Redis.ExternalPort)
	if redisPassword != "" {
		fmt.Printf("export REDIS_PASSWORD=%s\n", redisPassword)
	}
	// Prioritize using the database number from the environment configuration
	if envConfig.Redis.Database != 0 {
		fmt.Printf("export REDIS_DATABASE=%d\n", envConfig.Redis.Database)
	} else {
		fmt.Printf("export REDIS_DATABASE=%d\n", redisDatabase)
	}

	// Output SMTP configuration
	fmt.Printf("export SMTP_HOST=%s\n", envConfig.SMTP.Host)
	fmt.Printf("export SMTP_PORT=%d\n", envConfig.SMTP.Port)
	fmt.Printf("export SMTP_EXTERNAL_PORT=%d\n", envConfig.SMTP.ExternalPort)
	fmt.Printf("export SMTP_USERNAME=%s\n", cfg.SMTPConfig.Username)
	fmt.Printf("export SMTP_PASSWORD=%s\n", cfg.SMTPConfig.Password)
	fmt.Printf("export SMTP_FROM=%s\n", cfg.SMTPConfig.From)

	// Output Mailpit configuration
	fmt.Printf("export MAILPIT_WEB_PORT=%d\n", envConfig.Mailpit.WebPort)
	fmt.Printf("export MAILPIT_WEB_EXTERNAL_PORT=%d\n", envConfig.Mailpit.WebExternalPort)

	// Output Nginx configuration (only production environment)
	if envConfig.Nginx.HTTPPort != 0 {
		fmt.Printf("export NGINX_HTTP_PORT=%d\n", envConfig.Nginx.HTTPPort)
		fmt.Printf("export NGINX_HTTPS_PORT=%d\n", envConfig.Nginx.HTTPSPort)
	}

	// Output network configuration
	fmt.Printf("export NETWORK_NAME=%s\n", envConfig.Network.Name)
	fmt.Printf("export NETWORK_SUBNET=%s\n", envConfig.Network.Subnet)

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
