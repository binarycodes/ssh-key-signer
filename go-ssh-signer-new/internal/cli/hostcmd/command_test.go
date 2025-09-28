package hostcmd_test

import (
	"binarycodes/ssh-keysign/internal/cli/hostcmd"
	"binarycodes/ssh-keysign/internal/cli/testutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHostCmd_MissingKeyFails(t *testing.T) {
	cmd := hostcmd.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd)

	require.Error(t, err)
	require.Contains(t, err.Error(), "key and principals are required")
	require.Contains(t, stdout, "Usage:")
	require.Contains(t, stderr, "Error:")
}

func TestHostCmd_MissingOIDCFails(t *testing.T) {
	cmd := hostcmd.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub",
		"--principal", "web",
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "ca-server-url, client-id, client-secret, token-url required")
	require.Contains(t, stdout, "Usage:")
	require.Contains(t, stderr, "Error:")
}

func TestHostCmd_WithKeySucceeds(t *testing.T) {
	cmd := hostcmd.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd,
		"--key", "/tmp/id.pub",
		"--principal", "web",
		"--ca-server-url", "http://localhost:8888",
		"--client-id", "clientId",
		"--client-secret", "secret",
		"--token-url", "http://localhost:3939",
	)

	require.NoError(t, err)
	require.Contains(t, stdout, "duration=31536000")
	require.Empty(t, stderr)
}

func TestHostCmd_BadConfigFails(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "bad.yml")

	content := []byte("not: [valid\n")
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := hostcmd.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd, "--config", cfgPath)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read config")
	require.Contains(t, stdout, "Usage:")
	require.Contains(t, stderr, "Error:")
}

func TestHostCmd_WithValidConfigSucceeds(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "good.yml")

	content := []byte(`
host:
  key: "/tmp/id.pub"
  principal:
    - web
ca-server-url: "https://ca.example.test"
client-id: "client"
client-secret: "secret"
token-url: "https://idp.example.test/token"
`)
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cmd := hostcmd.NewCommand()
	stdout, stderr, err := testutil.ExecuteCommand(cmd, "--config", cfgPath)

	require.NoError(t, err)
	require.Contains(t, stdout, "[host]")
	require.Contains(t, stdout, "/tmp/id.pub")
	require.Contains(t, stdout, "web")
	require.Contains(t, stdout, "https://ca.example.test")
	require.Contains(t, stdout, "client")
	require.Contains(t, stdout, "https://idp.example.test/token")
	require.Contains(t, stdout, "3153600")

	require.NotContains(t, stdout, "secret")
	require.Empty(t, stderr)
}

func TestHostCmd_Precedence_ConfigEnvFlag(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yml")

	// Config sets key + principal
	content := []byte(`
host:
  key: "/from/config.pub"
  principal:
    - config_principal
ca_server_url: "https://ca.from.config"
client_id: "id_from_config"
client_secret: "secret_from_config"
token_url: "https://idp.from.config/token"
`)
	if err := os.WriteFile(cfgPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SSH_KEYSIGN_CLIENT_ID", "id_from_env")
	t.Setenv("SSH_KEYSIGN_CLIENT_SECRET", "secret_from_env")

	cmd := hostcmd.NewCommand()
	stdout, _, err := testutil.ExecuteCommand(cmd,
		"--config", cfgPath,
		"--key", "/from/flag.pub",
		"--principal", "flag_principal",
		"--ca-server-url", "https://ca.from.flag",
		"--token-url", "https://idp.from.flag/token",
	)

	require.NoError(t, err)
	require.Contains(t, stdout, "/from/flag.pub")        // flag > env > config
	require.Contains(t, stdout, "flag_principal")        // flag > config
	require.Contains(t, stdout, "id_from_env")           // env > config
	require.NotContains(t, stdout, "secret_from_env")    // secret should not be exposed
	require.Contains(t, stdout, "https://ca.from.flag")  // flag > config
	require.Contains(t, stdout, "https://idp.from.flag") // flag > config
}
