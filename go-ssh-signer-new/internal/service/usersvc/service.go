package usersvc

import (
	"context"

	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/service"
)

type UserService struct{}

type Service interface {
	SignUserKey(ctx context.Context, r *service.Runner) error
}

func (UserService) SignUserKey(ctx context.Context, r *service.Runner) error {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)

	cfg := r.Config
	log.Info("user run",
		zap.String("key", cfg.User.Key),
		zap.Strings("principal", cfg.User.Principals),
		zap.Uint64("duration", cfg.User.DurationSeconds),
		zap.String("ca-server-url", cfg.OAuth.ServerURL),
		zap.String("client-id", cfg.OAuth.ClientID),
		zap.String("token-url", cfg.OAuth.TokenURL),
	)

	p.V(logging.Verbose).Println("fetching key details")

	kType, key, err := r.KeyHandler.ReadPublicKey(ctx, cfg.User.Key)
	if err != nil {
		return err
	}

	p.V(logging.VeryVerbose).Printf("found key type: %v | public key: %v\n", kType, key)
	log.Info("public key details",
		zap.String("type", kType),
		zap.String("key", key),
	)

	p.V(logging.Verbose).Println("initiating connection to OAuth")

	// TODO: implement:
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file
	p.Println("[user] ok")
	return nil
}
