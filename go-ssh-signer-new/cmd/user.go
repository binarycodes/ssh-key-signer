package cmd

import (
	"binarycodes/ssh-keysign/internal/app"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Sign user SSH key and generate user ssh certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve values (flag/env/config)
			key := viper.GetString("user.key")
			principals := viper.GetStringSlice("user.principal")

			if key == "" {
				return app.ErrUsage("--key is required for user", cmd.Help)
			}

			if len(principals) == 0 {
				return app.ErrUsage("--principal is required for user", cmd.Help)
			}

			// Optional shared stuff
			dur := viper.GetUint64("duration")
			caURL := viper.GetString("ca_server_url") // optional for user
			clID := viper.GetString("client_id")
			clSecret := viper.GetString("client_secret")
			tURL := viper.GetString("token_url")

			_ = clSecret // keeps the declaration, compiler sees it as used
			// TODO: implement real logic; for now, just echo resolved inputs.
			fmt.Fprintf(os.Stdout, "[user] key=%s principal=%q duration=%d ca=%s client_id=%s token_url=%s\n", key, principals, dur, caURL, clID, tURL)
			return nil
		},
	}

	userCmd.Flags().String("key", "", "path to public key file (required)")
	userCmd.Flags().StringSlice("principal", nil, "comma-separated principal names (required)")

	// Optional: bind per-command keys to viper namespaced entries
	_ = viper.BindPFlag("user.key", userCmd.Flags().Lookup("key"))
	_ = viper.BindPFlag("user.principal", userCmd.Flags().Lookup("principal"))

	rootCmd.AddCommand(userCmd)
}
