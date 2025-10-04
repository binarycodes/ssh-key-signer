package config

import (
	"fmt"
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

	if c.OAuth.ServerURL == "" {
		missing = append(missing, "--ca-server-url / ca_server_url")
	}

	if c.OAuth.ClientID == "" {
		missing = append(missing, "--client-id / client_id")
	}

	if c.OAuth.ClientSecret == "" {
		missing = append(missing, "--client-secret / client_secret")
	}

	if c.OAuth.TokenURL == "" {
		missing = append(missing, "--token-url / token_url")
	}

	if len(missing) > 0 {
		return apperror.ErrUsage(fmt.Sprintf("host: missing required parameters: %s", strings.Join(missing, ", ")))
	}

	return nil
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
		return apperror.ErrUsage(fmt.Sprintf("user: missing required parameters: %s", strings.Join(missing, ", ")))
	}

	if c.OAuth.ServerURL == "" && c.OAuth.ClientID == "" && c.OAuth.ClientSecret == "" && c.OAuth.TokenURL == "" {
		return nil
	}

	if c.OAuth.ServerURL == "" || c.OAuth.ClientID == "" || c.OAuth.ClientSecret == "" || c.OAuth.TokenURL == "" {
		return apperror.ErrUsage("ca-server-url, client-id, client-secret, token-url either specify all or none")
	}

	return nil
}
