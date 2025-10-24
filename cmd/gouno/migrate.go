package gouno

import (
	"gosso/config"
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
	if err := viper.BindEnv("gouno_env"); err != nil {
		log.Fatalf("bind env failed, err: %v", err)
	}
	if err := viper.BindPFlag("gouno_env", cmd.Flags().Lookup("env")); err != nil {
		log.Fatalf("bind flag failed, err: %v", err)
	}
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
	//gormDB := database.NewGormDB(defaultDriver.Driver, defaultDriver.DSN, defaultDriver.LogLevel)

	clean := cmd.Flag("clean").Value.String() == "true"
	if clean {
		// if err := database.CleanMigrate(gormDB); err != nil {
		// 	log.Fatalf("clean tables failed, err: %v", err)
		// } else {
		// 	log.Println("clean tables success")
		// }
	} else {
		// if err := database.AutoMigrate(gormDB); err != nil {
		// 	log.Fatalf("auto migrate failed, err: %v", err)
		// } else {
		// 	log.Println("auto migrate success")
		// }
	}
}
