package usersvc

import (
	"context"
	"fmt"
	"io"

	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
)

func Run(ctx context.Context, out io.Writer, help apperror.HelpMethod, opts config.Options) error {
	log := ctxkeys.LoggerFrom(ctx)

	if err := opts.ValidateForUser(help); err != nil {
		return err
	}

	log.Info("user run",
		zap.String("key", opts.Key),
		zap.Strings("principal", opts.Principals),
		zap.Uint64("duration", opts.Duration),
		zap.String("ca-server-url", opts.CAServer),
		zap.String("client-id", opts.ClientID),
		zap.String("token-url", opts.TokenURL),
	)

	_, _ = fmt.Fprintln(out, "[user] ok")

	// TODO: implement:
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file
	return nil
}
