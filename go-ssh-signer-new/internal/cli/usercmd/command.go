package usercmd

import (
	"errors"

	"github.com/spf13/cobra"

	"binarycodes/ssh-keysign/internal/cli"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/usersvc"
)

func NewCommand() *cobra.Command {
	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Sign user SSH key and generate user ssh certificate",
		Long:  "Required (may come from flag, config, or env): --key, --principal",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())

			v.SetDefault("duration", constants.DefaultDurationForUserKey())

			err := errors.Join(
				v.BindPFlag("user.key", cmd.Flags().Lookup("key")),
				v.BindPFlag("user.principal", cmd.Flags().Lookup("principal")),
			)
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())
			opts := config.Options{
				Key:        v.GetString("user.key"),
				Principals: v.GetStringSlice("user.principal"),
				Duration:   v.GetUint64("duration"),
				CAServer:   v.GetString("ca-server-url"),
				ClientID:   v.GetString("client-id"),
				Secret:     v.GetString("client-secret"),
				TokenURL:   v.GetString("token-url"),
			}

			err := usersvc.Run(cmd.Context(), cmd.OutOrStdout(), cmd.Help, opts)
			return err
		},
	}

	userCmd.Flags().StringP("key", "k", "", "path to public key file")
	userCmd.Flags().StringSliceP("principal", "p", nil, "comma-separated principal names")

	cli.WireCommonFlags(userCmd)

	return userCmd
}
