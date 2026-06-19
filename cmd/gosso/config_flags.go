package gosso

import "github.com/spf13/cobra"

const defaultConfigPath = "./config"

func getConfigPath(cmd *cobra.Command) string {
	if f := cmd.Flag("config"); f != nil {
		return f.Value.String()
	}
	return defaultConfigPath
}
