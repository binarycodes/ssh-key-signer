package usercmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"binarycodes/ssh-keysign/internal/cli"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/service"
	"binarycodes/ssh-keysign/internal/service/cacert"
	"binarycodes/ssh-keysign/internal/service/keys"
	"binarycodes/ssh-keysign/internal/service/oauth"
	"binarycodes/ssh-keysign/internal/service/usersvc"
)

type Deps struct {
	Service usersvc.Service
}

func NewCommand(d Deps) *cobra.Command {
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

			runner := &service.Runner{
				Config:      cfg,
				KeyHandler:  keys.CAKeyHandler{},
				OAuthClient: oauth.CAAuthClient{},
				CertClient:  cacert.CACertClient{},
				CertHandler: cacert.CACertHandler{},
			}
			err := d.Service.SignUserKey(cmd.Context(), runner)
			return err
		},
	}

	userCmd.Flags().StringP("key", "k", "", "path to public key file")
	userCmd.Flags().StringSliceP("principal", "p", nil, "comma-separated principal names")
	userCmd.Flags().Uint64P("duration", "d", constants.DefaultDurationForUserKey(), "duration in seconds")
	userCmd.Flags().String("device-flow-url", "", "OIDC device flow URL")
	userCmd.Flags().String("token-poll-url", "", "OIDC token poll URL")

	cli.WireCommonFlags(userCmd)

	return userCmd
}
