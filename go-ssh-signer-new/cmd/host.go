package cmd

import (
	"binarycodes/ssh-keysign/internal/app"
	"binarycodes/ssh-keysign/internal/constants"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	hostCmd := &cobra.Command{
		Use:   "host",
		Short: "Sign host SSH key and generate host ssh certificate",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			viper.SetDefault("duration", constants.DefaultDurationForHostKey())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			key := viper.GetString("host.key")
			principal := viper.GetStringSlice("host.principal")

			if key == "" {
				return app.ErrUsage("--key is required for host", cmd.Help)
			}

			if len(principal) == 0 {
				return app.ErrUsage("--principal is required for host", cmd.Help)
			}

			caServerURL := viper.GetString("ca_server_url")
			clientID := viper.GetString("client_id")
			clientSecret := viper.GetString("client_secret")
			tokenURL := viper.GetString("token_url")
			missing := missingKeys(
				keyRequired{"--ca-server-url", caServerURL},
				keyRequired{"--client-id", clientID},
				keyRequired{"--client-secret", clientSecret},
				keyRequired{"--token-url", tokenURL},
			)
			if len(missing) > 0 {
				errorMessage := fmt.Sprintf("host: missing required settings: %s", strings.Join(missing, ", "))
				return app.ErrUsage(errorMessage, cmd.Help)
			}

			durationSeconds := viper.GetUint64("duration")

			// TODO: implement real logic
			fmt.Fprintf(os.Stdout, "[host] key=%s principal=%q duration=%d ca=%s client_id=%s token_url=%s\n", key, principal, durationSeconds, caServerURL, clientID, tokenURL)
			return nil
		},
	}

	hostCmd.Flags().StringP("key", "k", "", "path to public key file (required)")
	hostCmd.Flags().StringSliceP("principal", "p", nil, "space-separated principal names (required)")

	_ = viper.BindPFlag("host.key", hostCmd.Flags().Lookup("key"))
	_ = viper.BindPFlag("host.principal", hostCmd.Flags().Lookup("principal"))

	rootCmd.AddCommand(hostCmd)
}

type keyRequired struct{ name, val string }

func missingKeys(keysReq ...keyRequired) []string {
	var missingRequiredKeys []string
	for _, rkey := range keysReq {
		if strings.TrimSpace(rkey.val) == "" {
			missingRequiredKeys = append(missingRequiredKeys, rkey.name)
		}
	}
	return missingRequiredKeys
}
