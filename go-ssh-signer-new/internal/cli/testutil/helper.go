package testutil

import (
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"bytes"
	"context"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func ExecuteCommand(cmd *cobra.Command, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	v := viper.New()
	cmd.SetContext(ctxkeys.WithViper(context.Background(), v))

	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}
