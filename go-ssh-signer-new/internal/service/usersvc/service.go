package usersvc

import (
	"context"

	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
)

func Run(ctx context.Context, cfg config.Config) error {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)

	log.Info("user run",
		zap.String("key", cfg.User.Key),
		zap.Strings("principal", cfg.User.Principals),
		zap.Uint64("duration", cfg.User.DurationSeconds),
		zap.String("ca-server-url", cfg.OAuth.ServerURL),
		zap.String("client-id", cfg.OAuth.ClientID),
		zap.String("token-url", cfg.OAuth.TokenURL),
	)

	p.V(logging.VeryVerbose).Println("initiating connection to OAuth")
	p.Println("[user] ok")

	// TODO: implement:
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file
	return nil
}
