package gosso

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const defaultConfigPath = "./config"

func getConfigPath(cmd *cobra.Command) string {
	if f := cmd.Flag("config"); f != nil {
		return f.Value.String()
	}
	// Try relative to the executable's directory first (covers running the binary
	// from a different working directory), then fall back to current directory.
	if execPath, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(execPath), "config")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return candidate
		}
	}
	return defaultConfigPath
}
