package cmd

import (
	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/cli/hostkey"
	"binarycodes/ssh-keysign/internal/cli/userkey"
	"binarycodes/ssh-keysign/internal/cli/version"
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
				helpMethod()
				fmt.Fprintln(os.Stderr)
			}

			fmt.Fprintln(os.Stderr, err)
			os.Exit(kind.ExitCode())
		} else {
			fmt.Fprintln(os.Stderr, err)
		}

		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(version.NewCommand())
	rootCmd.AddCommand(hostkey.NewCommand())
	rootCmd.AddCommand(userkey.NewCommand())
}

func BuildRootCmd() *cobra.Command {
	// Intended for tests
	return rootCmd
}
