package usercmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"binarycodes/ssh-keysign/internal/cli"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/service/usersvc"
)

func NewCommand() *cobra.Command {
	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Sign user SSH key and generate user ssh certificate",
		Long:  "Required (may come from flag, config, or env): --key, --principal",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())

			err := errors.Join(
				v.BindPFlag("user.key", cmd.Flags().Lookup("key")),
				v.BindPFlag("user.principal", cmd.Flags().Lookup("principal")),
				v.BindPFlag("user.duration", cmd.Flags().Lookup("duration")),
			)
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())

			cfg, errC := config.Load(v)
			if errC != nil {
				return fmt.Errorf("invalid configuration: %w", errC)
			}

			if err := cfg.ValidateUser(); err != nil {
				return err
			}

			err := usersvc.Run(cmd.Context(), cfg)
			return err
		},
	}

	userCmd.Flags().StringP("key", "k", "", "path to public key file")
	userCmd.Flags().StringSliceP("principal", "p", nil, "comma-separated principal names")
	userCmd.Flags().Uint64P("duration", "d", constants.DefaultDurationForUserKey(), "duration in seconds")

	cli.WireCommonFlags(userCmd)

	return userCmd
}
