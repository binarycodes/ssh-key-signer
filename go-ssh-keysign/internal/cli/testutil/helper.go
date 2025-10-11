package testutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
)

func ExecuteCommand(t *testing.T, cmd *cobra.Command, args ...string) (stoutStr, stderrStr string, logs []observer.LoggedEntry, err error) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	ctx := context.Background()

	v := viper.New()
	ctx = ctxkeys.WithViper(ctx, v)

	obsCore, observed := observer.New(zap.InfoLevel)
	logger := zap.New(obsCore)
	ctx = ctxkeys.WithLogger(ctx, logger)

	pr := logging.NewPrinter(&stdout, int(logging.Normal))
	ctx = ctxkeys.WithPrinter(ctx, pr)

	cmd.SetContext(ctx)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)

	err = cmd.Execute()
	logs = observed.All()
	return stdout.String(), stderr.String(), logs, err
}

func LogContains(t *testing.T, log observer.LoggedEntry, key, val string) {
	t.Helper()

	var stringVal string
	if v, ok := log.ContextMap()[key]; ok && fmt.Sprintf("%v", v) == val {
		return
	} else if ok {
		stringVal = fmt.Sprintf("%v", v)
	}

	t.Fatalf("expected log to contain %s=%q, got %s | %#v", key, val, stringVal, log.ContextMap()[key])
}

func LogNotContains(t *testing.T, log observer.LoggedEntry, key string) {
	t.Helper()

	if _, ok := log.ContextMap()[key]; ok {
		t.Fatalf("expected log to not contain key=%s but it was found", key)
	}
}

func LogContainsValue(t *testing.T, log observer.LoggedEntry, val string) {
	t.Helper()

	require.Contains(t, fmt.Sprint(log.ContextMap()), val)
}

func LogNotContainsValue(t *testing.T, log observer.LoggedEntry, val string) {
	t.Helper()

	require.NotContains(t, fmt.Sprint(log.ContextMap()), val)
}

func ProjectPath(t *testing.T, elems ...string) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	cwd := dir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(append([]string{dir}, elems...)...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found while walking up from", cwd)
		}
		dir = parent
	}
}

func WriteTempFile(t *testing.T, filename string, content []byte) (fPath string) {
	t.Helper()

	tmp := t.TempDir()
	fPath = filepath.Join(tmp, filename)

	if err := os.WriteFile(fPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	return fPath
}
