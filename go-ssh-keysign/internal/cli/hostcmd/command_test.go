package hostcmd_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"binarycodes/ssh-keysign/internal/cli/hostcmd"
	"binarycodes/ssh-keysign/internal/cli/testutil"
	"binarycodes/ssh-keysign/internal/service"
)

type fakeHostService struct {
	called bool
	got    service.Runner
	err    error
}

func (f *fakeHostService) SignHostKey(ctx context.Context, r *service.Runner) error {
	f.called = true
	f.got = *r
	return f.err
}

func TestHostCmd_MissingKeyFails(t *testing.T) {
	fake := &fakeHostService{}
	cmd := hostcmd.NewCommand(hostcmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd)

	assert.Error(t, err)
	assert.NotEmpty(t, err.Error())
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stderr, "Error:")
	assert.Empty(t, logs)
}

func TestHostCmd_MissingOIDCFails(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

	fake := &fakeHostService{}
	cmd := hostcmd.NewCommand(hostcmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd,
		"--key", validKeyFilePath,
		"--principal", "web",
	)

	assert.Error(t, err)
	assert.NotEmpty(t, err.Error())
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stderr, "Error:")
	assert.Empty(t, logs)
}

func TestHostCmd_WithKeySucceeds(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

	fake := &fakeHostService{}
	cmd := hostcmd.NewCommand(hostcmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd,
		"--key", validKeyFilePath,
		"--principal", "web",
		"--ca-server-url", "http://localhost:8888",
		"--client-id", "clientId",
		"--client-secret", "secret",
		"--token-url", "http://localhost:3939",
	)

	assert.NoError(t, err)
	assert.Empty(t, stderr)
	assert.Empty(t, stdout)
	assert.Empty(t, logs)
	assert.Equal(t, true, fake.called)
	assert.Equal(t, uint64(31536000), fake.got.Config.Host.DurationSeconds)
}

func TestHostCmd_BadConfigFails(t *testing.T) {
	content := []byte("not: [valid\n")
	cfgPath := testutil.WriteTempFile(t, "config.yml", []byte(content))

	fake := &fakeHostService{}
	cmd := hostcmd.NewCommand(hostcmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd, "--config", cfgPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config")
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stderr, "Error:")
	assert.Empty(t, logs)
}

func TestHostCmd_WithValidConfigSucceeds(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

	content := fmt.Sprintf(`
host:
  key: %s
  principal:
    - web
ca-server-url: "https://ca.example.test"
client-id: "client"
client-secret: "secret"
token-url: "https://idp.example.test/token"
`, validKeyFilePath)

	cfgPath := testutil.WriteTempFile(t, "config.yml", []byte(content))

	fake := &fakeHostService{}
	cmd := hostcmd.NewCommand(hostcmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd, "--config", cfgPath)

	assert.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	assert.Empty(t, logs)

	assert.Equal(t, true, fake.called)
	assert.Equal(t, validKeyFilePath, fake.got.Config.Host.Key)
	assert.Equal(t, []string{"web"}, fake.got.Config.Host.Principals)
	assert.Equal(t, "https://ca.example.test", fake.got.Config.OAuth.ServerURL)
	assert.Equal(t, "client", fake.got.Config.OAuth.ClientID)
	assert.Equal(t, "secret", fake.got.Config.OAuth.ClientSecret)
	assert.Equal(t, "https://idp.example.test/token", fake.got.Config.OAuth.TokenURL)
	assert.Equal(t, uint64(31536000), fake.got.Config.Host.DurationSeconds)
}

func TestHostCmd_Precedence_ConfigEnvFlag(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

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
	cfgPath := testutil.WriteTempFile(t, "config.yml", content)

	t.Setenv("SSH_KEYSIGN_CLIENT_ID", "id_from_env")
	t.Setenv("SSH_KEYSIGN_CLIENT_SECRET", "secret_from_env")

	fake := &fakeHostService{}
	cmd := hostcmd.NewCommand(hostcmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd,
		"--config", cfgPath,
		"--key", validKeyFilePath,
		"--principal", "flag_principal",
		"--ca-server-url", "https://ca.from.flag",
		"--token-url", "https://idp.from.flag/token",
	)

	assert.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	assert.Empty(t, logs)

	assert.Equal(t, true, fake.called)
	assert.Equal(t, validKeyFilePath, fake.got.Config.Host.Key)
	assert.Equal(t, []string{"flag_principal"}, fake.got.Config.Host.Principals)
	assert.Equal(t, "https://ca.from.flag", fake.got.Config.OAuth.ServerURL)
	assert.Equal(t, "id_from_env", fake.got.Config.OAuth.ClientID)
	assert.Equal(t, "secret_from_env", fake.got.Config.OAuth.ClientSecret)
	assert.Equal(t, "https://idp.from.flag/token", fake.got.Config.OAuth.TokenURL)
	assert.Equal(t, uint64(31536000), fake.got.Config.Host.DurationSeconds)
}
