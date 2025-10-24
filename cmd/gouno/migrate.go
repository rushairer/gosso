package gouno

import (
	"database/sql"
	"fmt"
	"gosso/config"
	"log"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Database migration management",
	Long: `Database migration management using golang-migrate.
Available commands:
  migrate up [N]     - Apply all or N up migrations
  migrate down [N]   - Apply all or N down migrations  
  migrate drop       - Drop everything inside database
  migrate force V    - Set version V but don't run migration (ignores dirty state)
  migrate version    - Print current migration version
  migrate status     - Show migration status`,
}

var migrateUpCmd = &cobra.Command{
	Use:   "up [N]",
	Short: "Apply all or N up migrations",
	Args:  cobra.MaximumNArgs(1),
	Run:   runMigrateUp,
}

var migrateDownCmd = &cobra.Command{
	Use:   "down [N]",
	Short: "Apply all or N down migrations",
	Args:  cobra.MaximumNArgs(1),
	Run:   runMigrateDown,
}

var migrateDropCmd = &cobra.Command{
	Use:   "drop",
	Short: "Drop everything inside database",
	Run:   runMigrateDrop,
}

var migrateForceCmd = &cobra.Command{
	Use:   "force VERSION",
	Short: "Set version V but don't run migration (ignores dirty state)",
	Args:  cobra.ExactArgs(1),
	Run:   runMigrateForce,
}

var migrateVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print current migration version",
	Run:   runMigrateVersion,
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show migration status",
	Run:   runMigrateStatus,
}

func init() {
	// 添加全局标志
	migrateCmd.PersistentFlags().StringP("config_path", "c", "./config", "config file path")
	migrateCmd.PersistentFlags().StringP("env", "e", "development", "env: development, test, production")
	migrateCmd.PersistentFlags().StringP("migrations_path", "m", "./db/migrations", "migrations directory path")
	migrateCmd.PersistentFlags().StringP("schema", "s", "public", "database schema name")

	// 添加子命令
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateDropCmd)
	migrateCmd.AddCommand(migrateForceCmd)
	migrateCmd.AddCommand(migrateVersionCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
}

// 初始化配置和迁移实例
func initMigrate(cmd *cobra.Command) (*migrate.Migrate, error) {
	if err := viper.BindEnv("gouno_env"); err != nil {
		return nil, fmt.Errorf("bind env failed: %v", err)
	}
	if err := viper.BindPFlag("gouno_env", cmd.Flags().Lookup("env")); err != nil {
		return nil, fmt.Errorf("bind flag failed: %v", err)
	}
	env := viper.Get("gouno_env").(string)

	configPath := cmd.Flag("config_path").Value.String()
	if err := config.InitConfig(configPath, env); err != nil {
		return nil, fmt.Errorf("init config failed: %v", err)
	}

	defaultDriver := config.GlobalConfig.DatabaseConfig.GetDefaultDriver()
	if defaultDriver == nil {
		return nil, fmt.Errorf("default driver not found")
	}

	// 连接数据库
	db, err := sql.Open("pgx", defaultDriver.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// 获取 schema 参数
	schemaName := cmd.Flag("schema").Value.String()

	// 创建 postgres 驱动实例
	driver, err := postgres.WithInstance(db, &postgres.Config{
		MigrationsTable: "schema_migrations",
		DatabaseName:    "",         // 使用连接字符串中的数据库名
		SchemaName:      schemaName, // 使用参数指定的 schema
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres driver: %v", err)
	}

	// 获取迁移文件路径
	migrationsPath := cmd.Flag("migrations_path").Value.String()
	absPath, err := filepath.Abs(migrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	// 创建迁移实例
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", absPath),
		"postgres",
		driver,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrate instance: %v", err)
	}

	return m, nil
}

// closeMigrate 安全地关闭 migrate 实例并记录错误
func closeMigrate(m *migrate.Migrate) {
	if source, err := m.Close(); err != nil {
		log.Printf("Warning: Failed to close migrate instance: %v %v\n", source, err)
	}
}

func runMigrateUp(cmd *cobra.Command, args []string) {
	m, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)

	if len(args) > 0 {
		// 指定步数的 up 迁移
		steps := parseSteps(args[0])
		if err := m.Steps(steps); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration up %d steps failed: %v", steps, err)
		}
		log.Printf("Migration up %d steps completed successfully", steps)
	} else {
		// 全部 up 迁移
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration up failed: %v", err)
		}
		log.Println("Migration up completed successfully")
	}
}

func runMigrateDown(cmd *cobra.Command, args []string) {
	m, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)

	if len(args) > 0 {
		// 指定步数的 down 迁移
		steps := parseSteps(args[0])
		if err := m.Steps(-steps); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration down %d steps failed: %v", steps, err)
		}
		log.Printf("Migration down %d steps completed successfully", steps)
	} else {
		// 全部 down 迁移
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration down failed: %v", err)
		}
		log.Println("Migration down completed successfully")
	}
}

func runMigrateDrop(cmd *cobra.Command, args []string) {
	m, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)

	if err := m.Drop(); err != nil {
		log.Fatalf("Migration drop failed: %v", err)
	}
	log.Println("Database dropped successfully")
}

func runMigrateForce(cmd *cobra.Command, args []string) {
	m, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)

	version := parseVersion(args[0])
	if err := m.Force(version); err != nil {
		log.Fatalf("Migration force to version %d failed: %v", version, err)
	}
	log.Printf("Migration forced to version %d successfully", version)
}

func runMigrateVersion(cmd *cobra.Command, args []string) {
	m, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)

	version, dirty, err := m.Version()
	if err != nil {
		log.Fatalf("Failed to get migration version: %v", err)
	}

	status := "clean"
	if dirty {
		status = "dirty"
	}
	log.Printf("Current migration version: %d (status: %s)", version, status)
}

func runMigrateStatus(cmd *cobra.Command, args []string) {
	m, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)

	version, dirty, err := m.Version()
	if err != nil {
		if err == migrate.ErrNilVersion {
			log.Println("No migrations have been applied yet")
			return
		}
		log.Fatalf("Failed to get migration version: %v", err)
	}

	status := "clean"
	if dirty {
		status = "dirty"
	}

	log.Printf("Migration Status:")
	log.Printf("  Current Version: %d", version)
	log.Printf("  Status: %s", status)

	if dirty {
		log.Printf("  Warning: Database is in dirty state. Use 'migrate force VERSION' to resolve.")
	}
}

// 辅助函数
func parseSteps(s string) int {
	var steps int
	if _, err := fmt.Sscanf(s, "%d", &steps); err != nil {
		log.Fatalf("Invalid steps number: %s", s)
	}
	if steps <= 0 {
		log.Fatalf("Steps must be positive number, got: %d", steps)
	}
	return steps
}

func parseVersion(s string) int {
	var version int
	if _, err := fmt.Sscanf(s, "%d", &version); err != nil {
		log.Fatalf("Invalid version number: %s", s)
	}
	return version
}
