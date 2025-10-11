package usercmd_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"binarycodes/ssh-keysign/internal/cli/testutil"
	"binarycodes/ssh-keysign/internal/cli/usercmd"
	"binarycodes/ssh-keysign/internal/service"
)

type fakeUserService struct {
	called bool
	got    service.Runner
	err    error
}

func (f *fakeUserService) SignUserKey(ctx context.Context, r *service.Runner) error {
	f.called = true
	f.got = *r
	return f.err
}

func TestUsercmd_MissingKeyFails(t *testing.T) {
	fake := &fakeUserService{}
	cmd := usercmd.NewCommand(usercmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd)

	assert.Error(t, err)
	assert.NotEmpty(t, err.Error())
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stderr, "Error:")
	assert.Empty(t, logs)
}

func TestUsercmd_TokenURLIsOptional(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

	fake := &fakeUserService{}
	cmd := usercmd.NewCommand(usercmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd,
		"--key", validKeyFilePath,
		"--principal", "web",
		"--ca-server-url", "http://localhost:8888",
		"--client-id", "clientId",
		"--client-secret", "secret",
		"--device-flow-url", "http://localhost:3939/device",
		"--token-poll-url", "http://localhost:3939/token-poll",
	)

	assert.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	assert.Empty(t, logs)

	assert.Equal(t, true, fake.called)
	assert.Equal(t, validKeyFilePath, fake.got.Config.User.Key)
	assert.Equal(t, []string{"web"}, fake.got.Config.User.Principals)
	assert.Equal(t, "http://localhost:8888", fake.got.Config.OAuth.ServerURL)
	assert.Equal(t, "clientId", fake.got.Config.OAuth.ClientID)
	assert.Equal(t, "secret", fake.got.Config.OAuth.ClientSecret)
	assert.Equal(t, "", fake.got.Config.OAuth.TokenURL)
	assert.Equal(t, "http://localhost:3939/device", fake.got.Config.OAuth.DeviceFlowURL)
	assert.Equal(t, "http://localhost:3939/token-poll", fake.got.Config.OAuth.TokenPollURL)
	assert.Equal(t, uint64(1800), fake.got.Config.User.DurationSeconds)
}

func TestUsercmd_WithKeySucceeds(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

	fake := &fakeUserService{}
	cmd := usercmd.NewCommand(usercmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd,
		"--key", validKeyFilePath,
		"--principal", "web",
		"--ca-server-url", "http://localhost:8888",
		"--client-id", "clientId",
		"--client-secret", "secret",
		"--token-url", "http://localhost:3939",
	)

	assert.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	assert.Empty(t, logs)

	assert.Equal(t, true, fake.called)
	assert.Equal(t, validKeyFilePath, fake.got.Config.User.Key)
	assert.Equal(t, []string{"web"}, fake.got.Config.User.Principals)
	assert.Equal(t, "http://localhost:8888", fake.got.Config.OAuth.ServerURL)
	assert.Equal(t, "clientId", fake.got.Config.OAuth.ClientID)
	assert.Equal(t, "secret", fake.got.Config.OAuth.ClientSecret)
	assert.Equal(t, "http://localhost:3939", fake.got.Config.OAuth.TokenURL)
	assert.Equal(t, uint64(1800), fake.got.Config.User.DurationSeconds)
}

func TestUsercmd_BadConfigFails(t *testing.T) {
	content := []byte("not: [valid\n")
	cfgPath := testutil.WriteTempFile(t, "config.yml", []byte(content))

	fake := &fakeUserService{}
	cmd := usercmd.NewCommand(usercmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd, "--config", cfgPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config")
	assert.Contains(t, stdout, "Usage:")
	assert.Contains(t, stderr, "Error:")
	assert.Empty(t, logs)
}

func TestUsercmd_WithValidConfigSucceeds(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

	content := fmt.Sprintf(`
user:
  key: %s
  principal:
    - web
ca-server-url: "https://ca.example.test"
client-id: "client"
client-secret: "secret"
token-url: "https://idp.example.test/token"
`, validKeyFilePath)

	cfgPath := testutil.WriteTempFile(t, "config.yml", []byte(content))

	fake := &fakeUserService{}
	cmd := usercmd.NewCommand(usercmd.Deps{Service: fake})
	stdout, stderr, logs, err := testutil.ExecuteCommand(t, cmd, "--config", cfgPath)

	assert.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
	assert.Empty(t, logs)

	assert.Equal(t, true, fake.called)
	assert.Equal(t, validKeyFilePath, fake.got.Config.User.Key)
	assert.Equal(t, []string{"web"}, fake.got.Config.User.Principals)
	assert.Equal(t, "https://ca.example.test", fake.got.Config.OAuth.ServerURL)
	assert.Equal(t, "client", fake.got.Config.OAuth.ClientID)
	assert.Equal(t, "secret", fake.got.Config.OAuth.ClientSecret)
	assert.Equal(t, "https://idp.example.test/token", fake.got.Config.OAuth.TokenURL)
	assert.Equal(t, uint64(1800), fake.got.Config.User.DurationSeconds)
}

func TestUsercmd_Precedence_ConfigEnvFlag(t *testing.T) {
	validKeyFilePath := testutil.ProjectPath(t, "testdata", "id.pub")

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

	cfgPath := testutil.WriteTempFile(t, "config.yml", []byte(content))

	t.Setenv("SSH_KEYSIGN_CLIENT_ID", "id_from_env")
	t.Setenv("SSH_KEYSIGN_CLIENT_SECRET", "secret_from_env")

	fake := &fakeUserService{}
	cmd := usercmd.NewCommand(usercmd.Deps{Service: fake})
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
	assert.Equal(t, validKeyFilePath, fake.got.Config.User.Key)
	assert.Equal(t, []string{"flag_principal"}, fake.got.Config.User.Principals)
	assert.Equal(t, "https://ca.from.flag", fake.got.Config.OAuth.ServerURL)
	assert.Equal(t, "id_from_env", fake.got.Config.OAuth.ClientID)
	assert.Equal(t, "secret_from_env", fake.got.Config.OAuth.ClientSecret)
	assert.Equal(t, "https://idp.from.flag/token", fake.got.Config.OAuth.TokenURL)
	assert.Equal(t, uint64(1800), fake.got.Config.User.DurationSeconds)
}
