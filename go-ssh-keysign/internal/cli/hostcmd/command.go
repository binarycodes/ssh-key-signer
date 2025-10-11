package hostcmd

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
	"binarycodes/ssh-keysign/internal/service/hostsvc"
	"binarycodes/ssh-keysign/internal/service/keys"
	"binarycodes/ssh-keysign/internal/service/oauth"
)

type Deps struct {
	Service hostsvc.Service
}

func NewCommand(d Deps) *cobra.Command {
	hostCmd := &cobra.Command{
		Use:   "host",
		Short: "Sign host SSH key and generate host ssh certificate",
		Long:  "Required (may come from flag, config, or env): --ca-server-url, --client-id, --client-secret, --token-url, --key, --principal",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())

			err := errors.Join(
				v.BindPFlag("host.key", cmd.Flags().Lookup("key")),
				v.BindPFlag("host.principal", cmd.Flags().Lookup("principal")),
				v.BindPFlag("host.duration", cmd.Flags().Lookup("duration")),
			)
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			v := ctxkeys.ViperFrom(cmd.Context())

			cfg, errC := config.Load(v)
			if errC != nil {
				return fmt.Errorf("invalid configuration: %w", errC)
			}

			if err := cfg.ValidateHost(); err != nil {
				return err
			}

			runner := &service.Runner{
				Config:      cfg,
				KeyHandler:  keys.CAKeyHandler{},
				OAuthClient: oauth.CAAuthClient{},
				CertClient:  cacert.CACertClient{},
				CertHandler: cacert.CACertHandler{},
			}
			err := d.Service.SignHostKey(cmd.Context(), runner)
			return err
		},
	}

	hostCmd.Flags().StringP("key", "k", "", "path to public key file")
	hostCmd.Flags().StringSliceP("principal", "p", nil, "comma-separated principal names")
	hostCmd.Flags().Uint64P("duration", "d", constants.DefaultDurationForHostKey(), "duration in seconds")

	cli.WireCommonFlags(hostCmd)

	return hostCmd
}
