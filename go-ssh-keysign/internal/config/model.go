package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/service/paths"
)

type OAuth struct {
	ServerURL     string `mapstructure:"ca-server-url"`
	ClientID      string `mapstructure:"client-id"`
	ClientSecret  string `mapstructure:"client-secret"`
	TokenURL      string `mapstructure:"token-url"`
	DeviceFlowURL string `mapstructure:"device-flow-url"`
	TokenPollURL  string `mapstructure:"token-poll-url"`
}

func (o OAuth) HasClientCredential() bool {
	return o.ServerURL != "" && o.TokenURL != "" && o.ClientID != "" && o.ClientSecret != ""
}

func (o OAuth) HasDeviceFlow() bool {
	return o.ServerURL != "" && o.DeviceFlowURL != ""
}

type Host struct {
	Key             string   `mapstructure:"key"`
	Principals      []string `mapstructure:"principal"`
	DurationSeconds uint64   `mapstructure:"duration"`
}

type User struct {
	Key             string   `mapstructure:"key"`
	Principals      []string `mapstructure:"principal"`
	DurationSeconds uint64   `mapstructure:"duration"`
}

type Config struct {
	OAuth OAuth `mapstructure:",squash"`
	Host  Host  `mapstructure:"host"`
	User  User  `mapstructure:"user"`
}

func (c *Config) ValidateHost() error {
	var missing []string
	if c.Host.Key == "" {
		missing = append(missing, "--key")
	}

	if len(c.Host.Principals) == 0 {
		missing = append(missing, "--principal")
	}

	if len(missing) > 0 {
		return apperror.ErrUsage(fmt.Sprintf("missing required parameters: %s", strings.Join(missing, ", ")))
	}

	if c.OAuth.ServerURL == "" {
		return apperror.ErrUsage("--ca-server-url is required")
	}

	if _, err := ValidateClientCredential(c.OAuth, true); err != nil {
		return err
	}

	return ValidateKeyFile(c.Host.Key, false)
}

func (c *Config) ValidateUser() error {
	var missing []string

	if len(c.User.Principals) == 0 {
		missing = append(missing, "--principal")
	}

	if len(missing) > 0 {
		return apperror.ErrUsage(fmt.Sprintf("missing required parameters: %s", strings.Join(missing, ", ")))
	}

	if c.OAuth.ServerURL == "" {
		return apperror.ErrUsage("--ca-server-url is required")
	}

	clientCredentialConfigured, err := ValidateClientCredential(c.OAuth, false)
	if err != nil {
		return err
	}

	if !clientCredentialConfigured {
		if err := ValidateDeviceFlow(c.OAuth); err != nil {
			return err
		}
	}

	if c.User.Key != "" {
		return ValidateSSHAgent()
	}

	return ValidateKeyFile(c.User.Key, true)
}

func ValidateDeviceFlow(o OAuth) error {
	var missing []string

	if o.ClientID == "" {
		missing = append(missing, "--client-id")
	}

	if o.ClientSecret == "" {
		missing = append(missing, "--client-secret")
	}

	if o.DeviceFlowURL == "" {
		missing = append(missing, "--device-flow-url")
	}

	if o.TokenPollURL == "" {
		missing = append(missing, "--token-poll-url")
	}

	if len(missing) > 0 {
		return apperror.ErrUsage(fmt.Sprintf("missing required parameters: %s", strings.Join(missing, ", ")))
	}

	return nil
}

func ValidateClientCredential(o OAuth, required bool) (bool, error) {
	var missing []string

	if o.ClientID == "" {
		missing = append(missing, "--client-id")
	}

	if o.ClientSecret == "" {
		missing = append(missing, "--client-secret")
	}

	if o.TokenURL == "" {
		missing = append(missing, "--token-url")
	}

	if required && len(missing) > 0 {
		return false, apperror.ErrUsage(fmt.Sprintf("missing required parameters: %s", strings.Join(missing, ", ")))
	}

	return len(missing) == 0, nil
}

func ValidateKeyFile(keyfilePath string, opt bool) error {
	if opt && keyfilePath == "" {
		return nil
	}

	expandedKeyFilePath, err := paths.NormalizePath(keyfilePath)
	if err != nil {
		return apperror.ErrFileSystem(err)
	}

	extension := filepath.Ext(expandedKeyFilePath)
	if extension != ".pub" {
		return apperror.ErrUsage("only public key files are expected here. [Hint: name ending in .pub]")
	}

	if _, err := os.Stat(expandedKeyFilePath); err != nil {
		return apperror.ErrFileSystem(err)
	}

	return nil
}

func ValidateSSHAgent() error {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return apperror.ErrCert(errors.New("SSH_AUTH_SOCK not set; is ssh-agent running ?"))
	}
	return nil
}
