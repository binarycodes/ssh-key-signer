package testutil

import (
	"bytes"

	"github.com/spf13/cobra"
)

func ExecuteCommand(cmd *cobra.Command, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}
