package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/rushairer/gosso/config" // 引用项目的 config 包
	"github.com/rushairer/gosso/deploy" // 引用项目的 deploy 包
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
	// 支持多种 Redis DSN 格式:
	// redis://[:password@]host[:port][/database]
	// redis://:password@host:port/database
	// host:port
	// localhost:6379

	// 设置默认值
	host = "localhost"
	port = 6379
	database = 0

	if dsn == "" {
		return
	}

	// 处理 redis:// 协议
	if strings.HasPrefix(dsn, "redis://") {
		dsn = strings.TrimPrefix(dsn, "redis://")

		// 检查是否有密码
		if strings.Contains(dsn, "@") {
			parts := strings.SplitN(dsn, "@", 2)
			if len(parts) == 2 {
				// 提取密码部分
				authPart := parts[0]
				if strings.HasPrefix(authPart, ":") {
					password = strings.TrimPrefix(authPart, ":")
				}
				dsn = parts[1]
			}
		}

		// 检查是否有数据库编号
		if strings.Contains(dsn, "/") {
			parts := strings.SplitN(dsn, "/", 2)
			if len(parts) == 2 {
				database, _ = strconv.Atoi(parts[1])
				dsn = parts[0]
			}
		}

		// 解析 host:port
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
		// 简单的 host:port 格式
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
		log.Fatalf("❌ 用法: %s <environment>", os.Args[0])
	}

	env := os.Args[1]

	// 使用 config 包的 InitConfig 函数
	if err := config.InitConfig("config", env); err != nil {
		log.Fatalf("❌ 初始化配置失败: %v", err)
	}

	// 初始化部署配置
	if err := deploy.InitDeployConfig("deploy"); err != nil {
		log.Fatalf("❌ 初始化部署配置失败: %v", err)
	}

	// 直接使用 GlobalConfig
	cfg := config.GlobalConfig()

	// 获取环境配置
	envConfig, exists := deploy.GetEnvironment(env)
	if !exists {
		log.Fatalf("❌ 未找到环境配置: %s", env)
	}

	// 解析 PostgreSQL 配置
	pgDriver := cfg.DatabaseConfig.GetDriver("postgres")
	if pgDriver == nil {
		log.Fatalf("❌ 未找到 postgres 数据库配置")
	}

	pgUser, pgPassword, pgHost, _, pgDatabase := parsePostgresDSN(pgDriver.DSN)

	// 解析 Redis 配置
	redisHost, _, redisPassword, redisDatabase := parseRedisDSN(cfg.RedisConfig.DSN)

	// 输出应用配置
	fmt.Printf("export APP_PORT=%d\n", envConfig.App.Port)
	fmt.Printf("export APP_EXTERNAL_PORT=%d\n", envConfig.App.ExternalPort)
	fmt.Printf("export GIN_MODE=%s\n", envConfig.App.GinMode)
	fmt.Printf("export DEBUG=%t\n", envConfig.App.Debug)

	// 输出 PostgreSQL 配置（优先使用环境配置，回退到解析的配置）
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

	// 输出 Redis 配置
	fmt.Printf("export REDIS_HOST=%s\n", redisHost)
	fmt.Printf("export REDIS_PORT=%d\n", envConfig.Redis.Port)
	fmt.Printf("export REDIS_EXTERNAL_PORT=%d\n", envConfig.Redis.ExternalPort)
	if redisPassword != "" {
		fmt.Printf("export REDIS_PASSWORD=%s\n", redisPassword)
	}
	// 优先使用环境配置的数据库编号
	if envConfig.Redis.Database != 0 {
		fmt.Printf("export REDIS_DATABASE=%d\n", envConfig.Redis.Database)
	} else {
		fmt.Printf("export REDIS_DATABASE=%d\n", redisDatabase)
	}

	// 输出 SMTP 配置
	fmt.Printf("export SMTP_HOST=%s\n", envConfig.SMTP.Host)
	fmt.Printf("export SMTP_PORT=%d\n", envConfig.SMTP.Port)
	fmt.Printf("export SMTP_EXTERNAL_PORT=%d\n", envConfig.SMTP.ExternalPort)
	fmt.Printf("export SMTP_USERNAME=%s\n", cfg.SMTPConfig.Username)
	fmt.Printf("export SMTP_PASSWORD=%s\n", cfg.SMTPConfig.Password)
	fmt.Printf("export SMTP_FROM=%s\n", cfg.SMTPConfig.From)

	// 输出 Mailpit 配置
	fmt.Printf("export MAILPIT_WEB_PORT=%d\n", envConfig.Mailpit.WebPort)
	fmt.Printf("export MAILPIT_WEB_EXTERNAL_PORT=%d\n", envConfig.Mailpit.WebExternalPort)

	// 输出 Nginx 配置（仅生产环境）
	if envConfig.Nginx.HTTPPort != 0 {
		fmt.Printf("export NGINX_HTTP_PORT=%d\n", envConfig.Nginx.HTTPPort)
		fmt.Printf("export NGINX_HTTPS_PORT=%d\n", envConfig.Nginx.HTTPSPort)
	}

	// 输出网络配置
	fmt.Printf("export NETWORK_NAME=%s\n", envConfig.Network.Name)
	fmt.Printf("export NETWORK_SUBNET=%s\n", envConfig.Network.Subnet)

	// 输出配置信息到 stderr
	fmt.Fprintf(os.Stderr, "✅ %s 环境配置解析完成:\n", strings.ToUpper(env))
	fmt.Fprintf(os.Stderr, "  🌐 应用: %d -> %d (%s)\n", envConfig.App.ExternalPort, envConfig.App.Port, envConfig.App.GinMode)
	fmt.Fprintf(os.Stderr, "  🐘 PostgreSQL: %s:%d -> %d (DB: %s)\n", pgHost, envConfig.Postgres.ExternalPort, envConfig.Postgres.Port, envConfig.Postgres.Database)
	fmt.Fprintf(os.Stderr, "  🔴 Redis: %s:%d -> %d (DB: %d)\n", redisHost, envConfig.Redis.ExternalPort, envConfig.Redis.Port, envConfig.Redis.Database)
	fmt.Fprintf(os.Stderr, "  📧 SMTP: %s:%d -> %d\n", envConfig.SMTP.Host, envConfig.SMTP.ExternalPort, envConfig.SMTP.Port)
	fmt.Fprintf(os.Stderr, "  🌐 Mailpit Web: %d -> %d\n", envConfig.Mailpit.WebExternalPort, envConfig.Mailpit.WebPort)
	if envConfig.Nginx.HTTPPort != 0 {
		fmt.Fprintf(os.Stderr, "  🌐 Nginx: %d (HTTP), %d (HTTPS)\n", envConfig.Nginx.HTTPPort, envConfig.Nginx.HTTPSPort)
	}
	if redisPassword != "" {
		fmt.Fprintf(os.Stderr, "  🔐 Redis 密码: ***\n")
	}
}
