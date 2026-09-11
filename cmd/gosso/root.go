package gosso

import (
	"fmt"
	"os"

	"github.com/rushairer/gouno/generator"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gosso",
	Short: "gosso - SSO authentication server with OAuth2/OIDC support",
	Long: `gosso is a Single Sign-On (SSO) authentication server.
It provides OAuth2, OpenID Connect, WebAuthn/Passkey, and MFA support.`,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

func init() {
	rootCmd.AddCommand(webCmd, migrateCmd)
}

func Execute() {
	if _, err := generator.AttachProjectCommand(rootCmd, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading project commands: %v\n", err)
		os.Exit(1)
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing root command: %v\n", err)
		os.Exit(1)
	}
}
