package gouno

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
	rootCmd.AddCommand(generator.GeneratorCmd, webCmd, migrateCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing root command: %v\n", err)
		os.Exit(1)
	}
}
