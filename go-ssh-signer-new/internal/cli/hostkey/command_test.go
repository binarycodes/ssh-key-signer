package hostkey_test

import (
	"binarycodes/ssh-keysign/internal/cli/hostkey"
	"binarycodes/ssh-keysign/internal/cli/testutil"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestHostkey_MissingKeyFails(t *testing.T) {
	viper.Reset()

	cmd := hostkey.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd)

	if err == nil || !strings.Contains(err.Error(), "--key is required") {
		t.Fatalf("expected error about missing --key, got err=%v, stdout=%q, stderr=%q",
			err, stdout, stderr)
	}
}

func TestHostkey_MissingOIDCFails(t *testing.T) {
	viper.Reset()

	cmd := hostkey.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub", "--principal", "web",
	)

	if err == nil || !strings.Contains(err.Error(), "missing required settings") {
		t.Fatalf("expected error about missing keys, got error: %v (stdout=%q, stderr=%q)", err, stdout, stderr)
	}
}

func TestHostkey_WithKeySucceeds(t *testing.T) {
	viper.Reset()

	cmd := hostkey.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub", "--principal", "web", "--ca-server-url", "http://localhost:8888", "--client-id", "clientId", "--client-secret", "secret", "--token-url", "http://localhost:3939",
	)

	if err != nil {
		t.Fatalf("expected success, got error: %v (stdout=%q, stderr=%q)", err, stdout, stderr)
	}

	if !strings.Contains(stdout, "duration=31536000") {
		t.Errorf("expected output to mention duration=31536000, got stdout=%q", stdout)
	}
}
