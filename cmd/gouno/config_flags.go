package gouno

import "github.com/spf13/cobra"

const defaultConfigPath = "./config"

func getConfigPath(cmd *cobra.Command) string {
	if f := cmd.Flag("config"); f != nil && f.Changed {
		return f.Value.String()
	}
	if f := cmd.Flag("config_path"); f != nil && f.Changed {
		return f.Value.String()
	}
	if f := cmd.Flag("config"); f != nil {
		return f.Value.String()
	}
	return defaultConfigPath
}
