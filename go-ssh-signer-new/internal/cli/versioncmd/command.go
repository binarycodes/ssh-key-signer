package versioncmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"binarycodes/ssh-keysign/internal/meta"
)

func NewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"%s %s (commit %s, %s/%s, built with %s on %s)\n",
				cmd.Root().Name(), meta.Version, meta.Commit, meta.OS, meta.Arch, meta.GoVersion, meta.Date,
			)
			return err
		},
	}
}
