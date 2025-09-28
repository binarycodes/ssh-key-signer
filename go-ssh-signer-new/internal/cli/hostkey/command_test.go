package hostkey_test

import (
	"binarycodes/ssh-keysign/internal/cli/hostkey"
	"binarycodes/ssh-keysign/internal/cli/testutil"
	"strings"
	"testing"
)

func TestHostkey_MissingKeyFails(t *testing.T) {
	cmd := hostkey.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd)

	expected := "key and principals are required"
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected: %v, got: %v, stdout=%q, stderr=%q", expected, err, stdout, stderr)
	}
}

func TestHostkey_MissingOIDCFails(t *testing.T) {
	cmd := hostkey.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub",
		"--principal", "web",
	)

	expected := "ca-server-url, client-id, client-secret, token-url required"
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected: %v, got: %v (stdout=%q, stderr=%q)", expected, err, stdout, stderr)
	}
}

func TestHostkey_WithKeySucceeds(t *testing.T) {
	cmd := hostkey.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub",
		"--principal", "web",
		"--ca-server-url", "http://localhost:8888",
		"--client-id", "clientId",
		"--client-secret", "secret",
		"--token-url", "http://localhost:3939",
	)

	if err != nil {
		t.Fatalf("expected: success, got: %v (stdout=%q, stderr=%q)", err, stdout, stderr)
	}

	expected := "duration=31536000"
	if !strings.Contains(stdout, expected) {
		t.Errorf("expected: %v, got: stdout=%q", expected, stdout)
	}
}
