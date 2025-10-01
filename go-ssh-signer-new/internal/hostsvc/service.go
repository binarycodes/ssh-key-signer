package hostsvc

import (
	"context"
	"fmt"
	"io"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/model"
)

func Run(ctx context.Context, out io.Writer, help apperror.HelpMethod, o model.Options) error {
	if err := o.ValidateForHost(help); err != nil {
		return err
	}

	// TODO: implement real logic
	_, _ = fmt.Fprintf(out,
		"[host] key=%s principal=%q duration=%d ca=%s client_id=%s token_url=%s\n",
		o.Key, o.Principals, o.Duration, o.CAServer, o.ClientID, o.TokenURL)

	// TODO: implement:
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file
	return nil
}
