package cmd

import (
	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/cli/hostcmd"
	"binarycodes/ssh-keysign/internal/cli/usercmd"
	"binarycodes/ssh-keysign/internal/cli/versioncmd"
	"binarycodes/ssh-keysign/internal/constants"

	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           constants.AppName,
	Short:         "ssh key certificate generator - get ssh keys signed by the configured CA server",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {

		if kind := apperror.KindOf(err); kind != apperror.KUnknown {

			if helpMethod := apperror.HelpFor(err); helpMethod != nil {
				if err := helpMethod(); err != nil {
					os.Exit(apperror.KUnknown.ExitCode())
				}
				_, _ = fmt.Fprintln(rootCmd.ErrOrStderr())
			}

			_, _ = fmt.Fprintln(rootCmd.ErrOrStderr(), err)
			os.Exit(kind.ExitCode())
		} else {
			_, _ = fmt.Fprintln(rootCmd.ErrOrStderr(), err)
		}

		os.Exit(apperror.KUnknown.ExitCode())
	}
}

func init() {
	rootCmd.AddCommand(versioncmd.NewCommand())
	rootCmd.AddCommand(hostcmd.NewCommand())
	rootCmd.AddCommand(usercmd.NewCommand())
}

func BuildRootCmd() *cobra.Command {
	// Intended for tests
	return rootCmd
}
