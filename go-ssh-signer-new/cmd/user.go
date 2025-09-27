package cmd

import (
	"binarycodes/ssh-keysign/internal/app"
	"binarycodes/ssh-keysign/internal/constants"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Sign user SSH key and generate user ssh certificate",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			viper.SetDefault("duration", constants.DefaultDurationForUserKey())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			key := viper.GetString("user.key")
			principals := viper.GetStringSlice("user.principal")

			if key == "" {
				return app.ErrUsage("--key is required for user", cmd.Help)
			}

			if len(principals) == 0 {
				return app.ErrUsage("--principal is required for user", cmd.Help)
			}

			durationSeconds := viper.GetUint64("duration")
			caServerURL := viper.GetString("ca_server_url")
			clientID := viper.GetString("client_id")
			clientSecret := viper.GetString("client_secret")
			tokenURL := viper.GetString("token_url")

			_ = clientSecret // keeps the declaration, compiler sees it as used

			// TODO: implement real logic
			fmt.Fprintf(os.Stdout, "[user] key=%s principal=%q duration=%d ca=%s client_id=%s token_url=%s\n", key, principals, durationSeconds, caServerURL, clientID, tokenURL)

			return nil
		},
	}

	userCmd.Flags().StringP("key", "k", "", "path to public key file")
	userCmd.Flags().StringSliceP("principal", "p", nil, "comma-separated principal names")

	_ = viper.BindPFlag("user.key", userCmd.Flags().Lookup("key"))
	_ = viper.BindPFlag("user.principal", userCmd.Flags().Lookup("principal"))

	wireCommonFlags(userCmd)

	rootCmd.AddCommand(userCmd)
}
