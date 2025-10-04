package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"binarycodes/ssh-keysign/internal/apperror"
)

type OAuth struct {
	ServerURL    string `mapstructure:"ca-server-url"`
	ClientID     string `mapstructure:"client-id"`
	ClientSecret string `mapstructure:"client-secret"`
	TokenURL     string `mapstructure:"token-url"`
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
		missing = append(missing, "--key / host.key")
	}

	if len(c.Host.Principals) == 0 {
		missing = append(missing, "--principal / host.principal")
	}

	if len(missing) > 0 {
		return apperror.ErrUsage(fmt.Sprintf("missing required parameters: %s", strings.Join(missing, ", ")))
	}

	if err := ValidateOAuth(c.OAuth, true); err != nil {
		return err
	}

	return ValidateKeyFile(c.Host.Key)
}

func (c *Config) ValidateUser() error {
	var missing []string
	if c.User.Key == "" {
		missing = append(missing, "--key / user.key")
	}

	if len(c.User.Principals) == 0 {
		missing = append(missing, "--principal / user.principal")
	}

	if len(missing) > 0 {
		return apperror.ErrUsage(fmt.Sprintf("missing required parameters: %s", strings.Join(missing, ", ")))
	}

	if err := ValidateOAuth(c.OAuth, false); err != nil {
		return err
	}

	return ValidateKeyFile(c.User.Key)
}

func ValidateOAuth(o OAuth, required bool) error {
	var missing []string

	if !required {
		if o.ServerURL == "" && o.ClientID == "" && o.ClientSecret == "" && o.TokenURL == "" {
			return nil
		}

		if o.ServerURL == "" || o.ClientID == "" || o.ClientSecret == "" || o.TokenURL == "" {
			return apperror.ErrUsage("ca-server-url, client-id, client-secret, token-url either specify all or none")
		}
	}

	// validations for oauth required

	if o.ServerURL == "" {
		missing = append(missing, "--ca-server-url / ca_server_url")
	}

	if o.ClientID == "" {
		missing = append(missing, "--client-id / client_id")
	}

	if o.ClientSecret == "" {
		missing = append(missing, "--client-secret / client_secret")
	}

	if o.TokenURL == "" {
		missing = append(missing, "--token-url / token_url")
	}

	if len(missing) > 0 {
		return apperror.ErrUsage(fmt.Sprintf("missing required parameters: %s", strings.Join(missing, ", ")))
	}

	return nil
}

func ValidateKeyFile(keyfilePath string) error {
	extension := filepath.Ext(keyfilePath)
	if extension != ".pub" {
		return apperror.ErrUsage("only public key files are expected here. [Hint: name ending in .pub]")
	}

	if _, err := os.Stat(keyfilePath); err != nil {
		return apperror.ErrFileSystem(err)
	}

	return nil
}
