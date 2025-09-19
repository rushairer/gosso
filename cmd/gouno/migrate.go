package gouno

import (
	"gosso/config"
	"gosso/internal/database"
	"gosso/internal/domain"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate the database schema",
	Run:   startMigrate,
}

func init() {
	migrateCmd.Flags().StringP("config_path", "c", "./config", "config file path")
	migrateCmd.Flags().StringP("env", "e", "production", "env: development, test, production")
	migrateCmd.Flags().BoolP("clean", "", false, "clean all tables")
}

func startMigrate(cmd *cobra.Command, args []string) {
	viper.BindEnv("gouno_env")
	viper.BindPFlag("gouno_env", cmd.Flags().Lookup("env"))
	env := viper.Get("gouno_env").(string)

	configPath := cmd.Flag("config_path").Value.String()

	err := config.InitConfig(configPath, env)
	if err != nil {
		log.Fatalf("init config failed, err: %v", err)
	}

	defaultDriver := config.GlobalConfig.DatabaseConfig.GetDefaultDriver()
	if defaultDriver == nil {
		log.Fatalf("default driver not found")
	}
	gormDB := database.NewGormDB(defaultDriver.Driver, defaultDriver.DSN, defaultDriver.LogLevel)

	clean := cmd.Flag("clean").Value.String() == "true"
	if clean {
		if err := domain.CleanMigrate(gormDB); err != nil {
			log.Fatalf("clean tables failed, err: %v", err)
		}
	} else {

		if err := domain.AutoMigrate(gormDB); err != nil {
			log.Fatalf("auto migrate failed, err: %v", err)
		}
	}
}
