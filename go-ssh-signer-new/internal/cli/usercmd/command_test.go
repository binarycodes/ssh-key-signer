package usercmd_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"binarycodes/ssh-keysign/internal/cli/testutil"
	"binarycodes/ssh-keysign/internal/cli/usercmd"
)

func TestUsercmd_MissingKeyFails(t *testing.T) {
	cmd := usercmd.NewCommand()
	stdout, stderr, logs, err := testutil.ExecuteCommand(cmd)

	require.Error(t, err)
	require.Contains(t, err.Error(), "missing required parameters")
	require.Contains(t, stdout, "Usage:")
	require.Contains(t, stderr, "Error:")
	require.Empty(t, logs)
}

func TestUsercmd_OIDCIsOptional(t *testing.T) {
	cmd := usercmd.NewCommand()
	stdout, stderr, logs, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub",
		"--principal", "web",
	)

	require.NoError(t, err)
	require.Contains(t, stdout, "[user] ok")
	require.Empty(t, stderr)

	testutil.LogContains(t, logs[0], "key", "/tmp/id.pub")
	testutil.LogContains(t, logs[0], "principal", "[web]")

	require.Equal(t, "user run", logs[0].Message)
}

func TestUsercmd_WithKeySucceeds(t *testing.T) {
	cmd := usercmd.NewCommand()
	stdout, stderr, logs, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub",
		"--principal", "web",
		"--ca-server-url", "http://localhost:8888",
		"--client-id", "clientId",
		"--client-secret", "secret",
		"--token-url", "http://localhost:3939",
	)

	require.NoError(t, err)
	require.Contains(t, stdout, "[user] ok")
	require.Empty(t, stderr)
	testutil.LogContains(t, logs[0], "duration", "1800")
	require.Equal(t, "user run", logs[0].Message)
}

func TestUsercmd_BadConfigFails(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "bad.yml")

	content := []byte("not: [valid\n")
	if err := os.WriteFile(cfgPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := usercmd.NewCommand()
	stdout, stderr, logs, err := testutil.ExecuteCommand(cmd, "--config", cfgPath)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read config")
	require.Contains(t, stdout, "Usage:")
	require.Contains(t, stderr, "Error:")
	require.Empty(t, logs)
}

func TestUsercmd_WithValidConfigSucceeds(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "good.yml")

	content := []byte(`
user:
  key: "/tmp/id.pub"
  principal:
    - web
ca-server-url: "https://ca.example.test"
client-id: "client"
client-secret: "secret"
token-url: "https://idp.example.test/token"
`)
	if err := os.WriteFile(cfgPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := usercmd.NewCommand()
	stdout, stderr, logs, err := testutil.ExecuteCommand(cmd, "--config", cfgPath)

	require.NoError(t, err)
	require.Contains(t, stdout, "[user] ok")
	require.Empty(t, stderr)

	testutil.LogContains(t, logs[0], "key", "/tmp/id.pub")
	testutil.LogContains(t, logs[0], "principal", "[web]")
	testutil.LogContains(t, logs[0], "ca-server-url", "https://ca.example.test")
	testutil.LogContains(t, logs[0], "client-id", "client")
	testutil.LogContains(t, logs[0], "token-url", "https://idp.example.test/token")
	testutil.LogContains(t, logs[0], "duration", "1800")

	require.NotContains(t, stdout, "secret")
	testutil.LogNotContains(t, logs[0], "client-secret")

	for i := range logs {
		testutil.LogNotContainsValue(t, logs[i], "secret")
	}

	require.Empty(t, stderr)
	require.Equal(t, "user run", logs[0].Message)
}

func TestUsercmd_Precedence_ConfigEnvFlag(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yml")

	// Config sets key + principal
	content := []byte(`
user:
  key: "/from/config.pub"
  principal:
    - config_principal
ca_server_url: "https://ca.from.config"
client_id: "id_from_config"
client_secret: "secret_from_config"
token_url: "https://idp.from.config/token"
`)
	if err := os.WriteFile(cfgPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SSH_KEYSIGN_CLIENT_ID", "id_from_env")
	t.Setenv("SSH_KEYSIGN_CLIENT_SECRET", "secret_from_env")

	cmd := usercmd.NewCommand()
	stdout, stderr, logs, err := testutil.ExecuteCommand(cmd,
		"--config", cfgPath,
		"--key", "/from/flag.pub",
		"--principal", "flag_principal",
		"--ca-server-url", "https://ca.from.flag",
		"--token-url", "https://idp.from.flag/token",
	)

	require.NoError(t, err)
	require.Contains(t, stdout, "[user] ok")

	testutil.LogContains(t, logs[0], "key", "/from/flag.pub")
	testutil.LogContains(t, logs[0], "principal", "[flag_principal]")
	testutil.LogContains(t, logs[0], "ca-server-url", "https://ca.from.flag")
	testutil.LogContains(t, logs[0], "client-id", "id_from_env")
	testutil.LogContains(t, logs[0], "token-url", "https://idp.from.flag/token")
	testutil.LogContains(t, logs[0], "duration", "1800")

	require.NotContains(t, stdout, "secret_from_env")
	testutil.LogNotContains(t, logs[0], "client-secret")

	for i := range logs {
		testutil.LogNotContainsValue(t, logs[i], "secret_from_env")
	}

	require.Empty(t, stderr)
	require.Equal(t, "user run", logs[0].Message)
}
