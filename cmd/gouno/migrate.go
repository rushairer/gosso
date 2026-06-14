package gouno

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

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
	migrateCmd.PersistentFlags().StringP("config", "c", defaultConfigPath, "config directory path")
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
	configPath := getConfigPath(cmd)
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
		_ = db.Close()
		return nil, nil, fmt.Errorf("unsupported database driver: %q (only postgres is supported for migrations)", defaultDriver.Driver)
	}

	// Create postgres driver instance
	driver, err := postgres.WithInstance(db, &postgres.Config{
		MigrationsTable: "schema_migrations",
		DatabaseName:    "",         // Use database name from connection string
		SchemaName:      schemaName, // Use schema specified by parameter
	})
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Get migration file path
	migrationsPath := cmd.Flag("migrations_path").Value.String()
	absPath, err := filepath.Abs(migrationsPath)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", absPath),
		"postgres",
		driver,
	)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return m, db, nil
}

// closeMigrate safely closes the migrate instance and logs any errors.
func closeMigrate(m *migrate.Migrate) {
	if _, err := m.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to close migrate instance: %v\n", err)
	}
}

// withMigrateResources initializes migrate resources, runs the given function,
// then ensures proper cleanup. Returns the function's exit code.
func withMigrateResources(cmd *cobra.Command, fn func(*migrate.Migrate) error) {
	m, db, err := initMigrate(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Migration init failed: %v\n", err)
		os.Exit(1)
	}
	// Cleanup always runs — no deferred log.Fatal to skip it.
	err = fn(m)
	closeMigrate(m)
	_ = db.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func runMigrateUp(cmd *cobra.Command, args []string) {
	withMigrateResources(cmd, func(m *migrate.Migrate) error {
		if len(args) > 0 {
			steps, err := parseSteps(args[0])
			if err != nil {
				return err
			}
			if err := m.Steps(steps); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration up %d steps failed: %w", steps, err)
			}
			fmt.Printf("Migration up %d steps completed successfully\n", steps)
		} else {
			if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration up failed: %w", err)
			}
			fmt.Println("Migration up completed successfully")
		}
		return nil
	})
}

func runMigrateDown(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		fmt.Fprintln(os.Stderr, "Refusing to run destructive migration without --force flag. Use: migrate down --force")
		os.Exit(1)
	}

	withMigrateResources(cmd, func(m *migrate.Migrate) error {
		if len(args) > 0 {
			steps, err := parseSteps(args[0])
			if err != nil {
				return err
			}
			if err := m.Steps(-steps); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration down %d steps failed: %w", steps, err)
			}
			fmt.Printf("Migration down %d steps completed successfully\n", steps)
		} else {
			fmt.Println("WARNING: Rolling back ALL migrations")
			if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration down failed: %w", err)
			}
			fmt.Println("Migration down completed successfully")
		}
		return nil
	})
}

func runMigrateDrop(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")
	if !force {
		fmt.Fprintln(os.Stderr, "Refusing to drop database without --force flag. Use: migrate drop --force")
		os.Exit(1)
	}

	withMigrateResources(cmd, func(m *migrate.Migrate) error {
		if err := m.Drop(); err != nil {
			return fmt.Errorf("migration drop failed: %w", err)
		}
		fmt.Println("Database dropped successfully")
		return nil
	})
}

func runMigrateForce(cmd *cobra.Command, args []string) {
	withMigrateResources(cmd, func(m *migrate.Migrate) error {
		version, err := parseVersion(args[0])
		if err != nil {
			return err
		}
		if err := m.Force(version); err != nil {
			return fmt.Errorf("migration force to version %d failed: %w", version, err)
		}
		fmt.Printf("Migration forced to version %d successfully\n", version)
		return nil
	})
}

func runMigrateVersion(cmd *cobra.Command, args []string) {
	withMigrateResources(cmd, func(m *migrate.Migrate) error {
		version, dirty, err := m.Version()
		if err != nil {
			return fmt.Errorf("failed to get migration version: %w", err)
		}

		status := "clean"
		if dirty {
			status = "dirty"
		}
		fmt.Printf("Current migration version: %d (status: %s)\n", version, status)
		return nil
	})
}

func runMigrateStatus(cmd *cobra.Command, args []string) {
	withMigrateResources(cmd, func(m *migrate.Migrate) error {
		version, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				fmt.Println("No migrations have been applied yet")
				return nil
			}
			return fmt.Errorf("failed to get migration version: %w", err)
		}

		status := "clean"
		if dirty {
			status = "dirty"
		}

		fmt.Printf("Migration Status:\n")
		fmt.Printf("  Current Version: %d\n", version)
		fmt.Printf("  Status: %s\n", status)

		if dirty {
			fmt.Printf("  Warning: Database is in dirty state. Use 'migrate force VERSION' to resolve.\n")
		}
		return nil
	})
}

// parseSteps parses a step count string using strconv.Atoi for idiomatic Go parsing.
func parseSteps(s string) (int, error) {
	steps, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid steps number: %s", s)
	}
	if steps <= 0 {
		return 0, fmt.Errorf("steps must be positive number, got: %d", steps)
	}
	return steps, nil
}

// parseVersion parses a version string using strconv.Atoi for idiomatic Go parsing.
func parseVersion(s string) (int, error) {
	version, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid version number: %s", s)
	}
	if version < 0 {
		return 0, fmt.Errorf("version must be non-negative, got: %d", version)
	}
	return version, nil
}
