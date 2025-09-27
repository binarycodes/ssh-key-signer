package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	hostCmd := &cobra.Command{
		Use:   "host",
		Short: "Host flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			key := viper.GetString("host.key")
			principal := viper.GetStringSlice("host.principal")

			if key == "" {
				return fmt.Errorf("--key is required for host")
			}
			if len(principal) == 0 {
				return fmt.Errorf("--principal is required for host")
			}

			// Mandatory for host (from flags or config)
			caURL := viper.GetString("ca_server_url")
			clID := viper.GetString("client_id")
			clSecret := viper.GetString("client_secret")
			tURL := viper.GetString("token_url")
			missing := missingKeys(
				keyReq{"--ca-server-url", caURL},
				keyReq{"--client-id", clID},
				keyReq{"--client-secret", clSecret},
				keyReq{"--token-url", tURL},
			)
			if len(missing) > 0 {
				return fmt.Errorf("host: missing required settings: %s", strings.Join(missing, ", "))
			}

			dur := viper.GetUint64("duration")

			// TODO: implement real logic; for now, echo resolved inputs.
			fmt.Fprintf(os.Stdout, "[host] key=%s principal=%q duration=%d ca=%s client_id=%s token_url=%s\n", key, principal, dur, caURL, clID, tURL)
			return nil
		},
	}

	hostCmd.Flags().String("key", "", "path to public key file (required)")
	hostCmd.Flags().StringSlice("principal", nil, "space-separated principal names (required)")

	_ = viper.BindPFlag("host.key", hostCmd.Flags().Lookup("key"))
	_ = viper.BindPFlag("host.principal", hostCmd.Flags().Lookup("principal"))

	rootCmd.AddCommand(hostCmd)
}

type keyReq struct{ name, val string }

func missingKeys(reqs ...keyReq) []string {
	var m []string
	for _, r := range reqs {
		if strings.TrimSpace(r.val) == "" {
			m = append(m, r.name)
		}
	}
	return m
}
