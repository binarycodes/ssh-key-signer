package hostsvc

import (
	"context"
	"fmt"
	"io"

	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
)

func Run(ctx context.Context, out io.Writer, help apperror.HelpMethod, cfg config.Config) error {
	log := ctxkeys.LoggerFrom(ctx)

	log.Info("host run",
		zap.String("key", cfg.Host.Key),
		zap.Strings("principal", cfg.Host.Principals),
		zap.Uint64("duration", cfg.Host.DurationSeconds),
		zap.String("ca-server-url", cfg.OAuth.ServerURL),
		zap.String("client-id", cfg.OAuth.ClientID),
		zap.String("token-url", cfg.OAuth.TokenURL),
	)

	_, _ = fmt.Fprintln(out, "[host] ok")

	// TODO: implement:
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file
	return nil
}
