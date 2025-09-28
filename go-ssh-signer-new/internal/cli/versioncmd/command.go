package versioncmd

import (
	"binarycodes/ssh-keysign/internal/meta"
	"fmt"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s %s (commit %s, %s/%s, built with %s on %s)\n",
				cmd.Root().Name(), meta.Version, meta.Commit, meta.OS, meta.Arch, meta.GoVersion, meta.Date,
			)
		},
	}
}
