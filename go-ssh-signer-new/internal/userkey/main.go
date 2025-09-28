package userkey

import (
	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/model"
	"context"
	"fmt"
	"io"
)

func Run(ctx context.Context, out io.Writer, help apperror.HelpMethod, o model.Options) error {
	if err := o.ValidateForUser(help); err != nil {
		return err
	}

	// TODO: implement:
	fmt.Fprintf(out,
		"[user] key=%s principal=%q duration=%d ca=%s client_id=%s token_url=%s\n",
		o.Key, o.Principals, o.Duration, o.CAServer, o.ClientID, o.TokenURL)
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file
	return nil
}
