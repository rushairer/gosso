package gouno

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"

	"github.com/rushairer/gosso/config"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"
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
	// Add global flags
	migrateCmd.PersistentFlags().StringP("config_path", "c", "./config", "config file path")
	migrateCmd.PersistentFlags().StringP("env", "e", "production", "env: development, test, production")
	migrateCmd.PersistentFlags().StringP("migrations_path", "m", "./db/migrations", "migrations directory path")
	migrateCmd.PersistentFlags().StringP("schema", "s", "public", "database schema name")

	// Safety flag for destructive operations
	migrateDownCmd.Flags().Bool("force", false, "required to confirm destructive down migration")
	migrateDropCmd.Flags().Bool("force", false, "required to confirm database drop")

	// Add subcommands
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateDropCmd)
	migrateCmd.AddCommand(migrateForceCmd)
	migrateCmd.AddCommand(migrateVersionCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
}

// initMigrate initializes configuration and creates a migrate instance.
// Returns the migrate instance and the underlying *sql.DB (caller must close both).
func initMigrate(cmd *cobra.Command) (*migrate.Migrate, *sql.DB, error) {
	configPath := cmd.Flag("config_path").Value.String()
	env := cmd.Flag("env").Value.String()

	configManager, err := config.NewConfigManager(cmd, configPath, env)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	globalConfig := configManager.Config()

	defaultDriver := globalConfig.DatabaseConfig.GetDefaultDriver()
	if defaultDriver == nil {
		return nil, nil, fmt.Errorf("default driver not found")
	}

	// Connect to database
	db, err := sql.Open(defaultDriver.Driver, defaultDriver.DSN)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get schema parameter
	schemaName := cmd.Flag("schema").Value.String()

	if defaultDriver.Driver != "postgres" {
		return nil, nil, fmt.Errorf("unsupported database driver: %q (only postgres is supported for migrations)", defaultDriver.Driver)
	}

	// Create postgres driver instance
	driver, err := postgres.WithInstance(db, &postgres.Config{
		MigrationsTable: "schema_migrations",
		DatabaseName:    "",         // Use database name from connection string
		SchemaName:      schemaName, // Use schema specified by parameter
	})
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Get migration file path
	migrationsPath := cmd.Flag("migrations_path").Value.String()
	absPath, err := filepath.Abs(migrationsPath)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", absPath),
		"postgres",
		driver,
	)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return m, db, nil
}

// closeMigrate safely closes the migrate instance and logs any errors
func closeMigrate(m *migrate.Migrate) {
	if _, err := m.Close(); err != nil {
		fmt.Printf("Warning: Failed to close migrate instance: %v\n", err)
	}
}

func runMigrateUp(cmd *cobra.Command, args []string) {
	m, db, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)
	defer db.Close()

	if len(args) > 0 {
		// Up migration with specified step count
		steps := parseSteps(args[0])
		if err := m.Steps(steps); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration up %d steps failed: %v", steps, err)
		}
		log.Printf("Migration up %d steps completed successfully", steps)
	} else {
		// Run all up migrations
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration up failed: %v", err)
		}
		log.Println("Migration up completed successfully")
	}
}

func runMigrateDown(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		log.Fatal("Refusing to run destructive migration without --force flag. Use: migrate down --force")
	}

	m, db, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)
	defer db.Close()

	if len(args) > 0 {
		// Down migration with specified step count
		steps := parseSteps(args[0])
		if err := m.Steps(-steps); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration down %d steps failed: %v", steps, err)
		}
		log.Printf("Migration down %d steps completed successfully", steps)
	} else {
		// Run all down migrations
		log.Println("WARNING: Rolling back ALL migrations")
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("Migration down failed: %v", err)
		}
		log.Println("Migration down completed successfully")
	}
}

func runMigrateDrop(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		log.Fatal("Refusing to drop database without --force flag. Use: migrate drop --force")
	}

	m, db, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)
	defer db.Close()

	if err := m.Drop(); err != nil {
		log.Fatalf("Migration drop failed: %v", err)
	}
	log.Println("Database dropped successfully")
}

func runMigrateForce(cmd *cobra.Command, args []string) {
	m, db, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)
	defer db.Close()

	version := parseVersion(args[0])
	if err := m.Force(version); err != nil {
		log.Fatalf("Migration force to version %d failed: %v", version, err)
	}
	log.Printf("Migration forced to version %d successfully", version)
}

func runMigrateVersion(cmd *cobra.Command, args []string) {
	m, db, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)
	defer db.Close()

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
	m, db, err := initMigrate(cmd)
	if err != nil {
		log.Fatalf("Migration init failed: %v", err)
	}
	defer closeMigrate(m)
	defer db.Close()

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

// Helper functions
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
	if version < 0 {
		log.Fatalf("Version must be non-negative, got: %d", version)
	}
	return version
}
