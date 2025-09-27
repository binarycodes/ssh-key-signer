package cmd

import (
	"binarycodes/ssh-keysign/internal/meta"
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s %s (commit %s, built %s, %s/%s)\n",
				cmd.Root().Name(), meta.Version, meta.Commit, meta.Date, meta.OS, meta.Arch,
			)
		},
	}
}
