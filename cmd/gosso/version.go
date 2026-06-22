package gosso

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Set via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  "Print the gosso build version, commit hash, build date, and Go runtime version.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("gosso %s\n", version)
		fmt.Printf("  commit:    %s\n", commit)
		fmt.Printf("  built:     %s\n", date)
		fmt.Printf("  go:        %s\n", runtime.Version())
		fmt.Printf("  os/arch:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
