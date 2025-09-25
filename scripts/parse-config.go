package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type WebServerConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

type DatabaseDriver struct {
	Name     string `yaml:"name"`
	Driver   string `yaml:"driver"`
	DSN      string `yaml:"dsn"`
	LogLevel int    `yaml:"log_level"`
}

type DatabaseConfig struct {
	Default string                    `yaml:"default"`
	Drivers map[string]DatabaseDriver `yaml:"drivers"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
}

type Config struct {
	WebServer WebServerConfig `yaml:"web_server"`
	Database  DatabaseConfig  `yaml:"database"`
	SMTP      SMTPConfig      `yaml:"smtp"`
}

func parseMySQLDSN(dsn string) (user, password, host string, port int, database string) {
	// user:password@tcp(host:port)/database?params
	re := regexp.MustCompile(`([^:]+):([^@]+)@tcp\(([^:]+):(\d+)\)/([^?]+)`)
	matches := re.FindStringSubmatch(dsn)
	if len(matches) == 6 {
		user = matches[1]
		password = matches[2]
		host = matches[3]
		port, _ = strconv.Atoi(matches[4])
		database = matches[5]
	}
	return
}

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

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("❌ 用法: %s <environment>", os.Args[0])
	}

	env := os.Args[1]
	configFile := fmt.Sprintf("config/%s.yaml", env)

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Fatalf("❌ 配置文件不存在: %s", configFile)
	}

	fmt.Fprintf(os.Stderr, "📋 从 %s 解析 %s 环境配置...\n", configFile, env)

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("❌ 读取配置文件失败: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("❌ 解析配置文件失败: %v", err)
	}

	// 解析 MySQL 配置
	mysqlUser, mysqlPassword, _, mysqlPort, mysqlDatabase := parseMySQLDSN(config.Database.Drivers["mysql"].DSN)

	// 解析 PostgreSQL 配置
	pgUser, pgPassword, _, pgPort, pgDatabase := parsePostgresDSN(config.Database.Drivers["postgres"].DSN)

	// 输出环境变量
	fmt.Printf("export APP_PORT=%d\n", config.WebServer.Port)
	fmt.Printf("export MYSQL_DATABASE=%s\n", mysqlDatabase)
	fmt.Printf("export MYSQL_USER=%s\n", mysqlUser)
	fmt.Printf("export MYSQL_PASSWORD=%s\n", mysqlPassword)
	fmt.Printf("export MYSQL_EXTERNAL_PORT=%d\n", mysqlPort)

	fmt.Printf("export POSTGRES_DB=%s\n", pgDatabase)
	fmt.Printf("export POSTGRES_USER=%s\n", pgUser)
	fmt.Printf("export POSTGRES_PASSWORD=%s\n", pgPassword)
	fmt.Printf("export POSTGRES_EXTERNAL_PORT=%d\n", pgPort)

	fmt.Printf("export SMTP_EXTERNAL_PORT=%d\n", config.SMTP.Port)

	// 根据环境设置不同的端口映射
	var mailpitWebPort int
	switch env {
	case "test":
		mailpitWebPort = 8025 + config.SMTP.Port - 1025
	case "development":
		mailpitWebPort = 8026 + config.SMTP.Port - 1026
	default:
		mailpitWebPort = 8025
	}
	fmt.Printf("export MAILPIT_WEB_EXTERNAL_PORT=%d\n", mailpitWebPort)

	// Redis 端口根据环境设置
	var redisPort int
	switch env {
	case "test":
		redisPort = 6381
	case "development":
		redisPort = 6380
	default:
		redisPort = 6379
	}
	fmt.Printf("export REDIS_EXTERNAL_PORT=%d\n", redisPort)

	// 输出配置信息到 stderr
	fmt.Fprintf(os.Stderr, "✅ %s 环境配置解析完成:\n", strings.ToUpper(env))
	fmt.Fprintf(os.Stderr, "  🌐 应用端口: %d\n", config.WebServer.Port)
	fmt.Fprintf(os.Stderr, "  🗄️  MySQL: 外部端口 %d -> 内部端口 3306\n", mysqlPort)
	fmt.Fprintf(os.Stderr, "  🐘 PostgreSQL: 外部端口 %d -> 内部端口 5432\n", pgPort)
	fmt.Fprintf(os.Stderr, "  📧 SMTP: 外部端口 %d -> 内部端口 1025\n", config.SMTP.Port)
	fmt.Fprintf(os.Stderr, "  🌐 Mailpit Web: 外部端口 %d -> 内部端口 8025\n", mailpitWebPort)
	fmt.Fprintf(os.Stderr, "  🔴 Redis: 外部端口 %d -> 内部端口 6379\n", redisPort)
}
