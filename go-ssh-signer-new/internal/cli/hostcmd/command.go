package hostcmd

import (
	"github.com/spf13/cobra"

	"binarycodes/ssh-keysign/internal/cli"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/hostsvc"
	"binarycodes/ssh-keysign/internal/model"
)

func NewCommand() *cobra.Command {
	hostCmd := &cobra.Command{
		Use:   "host",
		Short: "Sign host SSH key and generate host ssh certificate",
		Long:  "Required (may come from flag, config, or env): --ca-server-url, --client-id, --client-secret, --token-url, --key, --principal",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())

			v.SetDefault("duration", constants.DefaultDurationForHostKey())
			_ = v.BindPFlag("host.key", cmd.Flags().Lookup("key"))
			_ = v.BindPFlag("host.principal", cmd.Flags().Lookup("principal"))

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())
			opts := model.Options{
				Key:        v.GetString("host.key"),
				Principals: v.GetStringSlice("host.principal"),
				Duration:   v.GetUint64("duration"),
				CAServer:   v.GetString("ca-server-url"),
				ClientID:   v.GetString("client-id"),
				Secret:     v.GetString("client-secret"),
				TokenURL:   v.GetString("token-url"),
			}

			if err := hostsvc.Run(cmd.Context(), cmd.OutOrStdout(), cmd.Help, opts); err != nil {
				return err
			}

			return nil
		},
	}

	hostCmd.Flags().StringP("key", "k", "", "path to public key file")
	hostCmd.Flags().StringSliceP("principal", "p", nil, "comma-separated principal names")

	cli.WireCommonFlags(hostCmd)

	return hostCmd
}
