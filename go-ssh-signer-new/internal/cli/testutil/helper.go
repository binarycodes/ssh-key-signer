package testutil

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"binarycodes/ssh-keysign/internal/ctxkeys"
)

func ExecuteCommand(cmd *cobra.Command, args ...string) (stoutStr, stderrStr string, logs []observer.LoggedEntry, err error) {
	var stdout, stderr bytes.Buffer

	ctx := context.Background()

	v := viper.New()
	ctx = ctxkeys.WithViper(ctx, v)

	obsCore, observed := observer.New(zap.InfoLevel)
	logger := zap.New(obsCore)
	ctx = ctxkeys.WithLogger(ctx, logger)

	cmd.SetContext(ctx)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)

	err = cmd.Execute()
	logs = observed.All()
	return stdout.String(), stderr.String(), logs, err
}

func LogContains(t *testing.T, log observer.LoggedEntry, key, val string) {
	var stringVal string
	if v, ok := log.ContextMap()[key]; ok && fmt.Sprintf("%v", v) == val {
		return
	} else if ok {
		stringVal = fmt.Sprintf("%v", v)
	}

	t.Fatalf("expected log to contain %s=%q, got %s | %#v", key, val, stringVal, log.ContextMap()[key])
}

func LogNotContains(t *testing.T, log observer.LoggedEntry, key string) {
	if _, ok := log.ContextMap()[key]; ok {
		t.Fatalf("expected log to not contain key=%s but it was found", key)
	}
}

func LogContainsValue(t *testing.T, log observer.LoggedEntry, val string) {
	require.Contains(t, fmt.Sprint(log.ContextMap()), val)
}

func LogNotContainsValue(t *testing.T, log observer.LoggedEntry, val string) {
	require.NotContains(t, fmt.Sprint(log.ContextMap()), val)
}
