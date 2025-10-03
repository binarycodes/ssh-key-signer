package config

import (
	"binarycodes/ssh-keysign/internal/apperror"
)

type Options struct {
	Key        string
	Principals []string
	Duration   uint64 /* in seconds */
	CAServer   string
	ClientID   string
	Secret     string
	TokenURL   string
}

func (o Options) ValidateForHost(help apperror.HelpMethod) error {
	if o.Key == "" || len(o.Principals) == 0 {
		return apperror.ErrUsage("key and principals are required", help)
	}

	if o.CAServer == "" || o.ClientID == "" || o.Secret == "" || o.TokenURL == "" {
		return apperror.ErrUsage("ca-server-url, client-id, client-secret, token-url required", help)
	}

	return nil
}

func (o Options) ValidateForUser(help apperror.HelpMethod) error {
	if o.Key == "" || len(o.Principals) == 0 {
		return apperror.ErrUsage("key and principals are required", help)
	}

	if o.CAServer == "" && o.ClientID == "" && o.Secret == "" && o.TokenURL == "" {
		return nil
	}

	if o.CAServer == "" || o.ClientID == "" || o.Secret == "" || o.TokenURL == "" {
		return apperror.ErrUsage("ca-server-url, client-id, client-secret, token-url either specify all or none", help)
	}

	return nil
}
