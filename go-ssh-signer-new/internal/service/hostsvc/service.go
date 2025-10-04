package hostsvc

import (
	"context"

	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/service"
)

type HostService struct{}

type Service interface {
	SignHostKey(ctx context.Context, r *service.Runner) error
}

func (HostService) SignHostKey(ctx context.Context, r *service.Runner) error {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)

	cfg := r.Config
	log.Info("host run",
		zap.String("key", cfg.Host.Key),
		zap.Strings("principal", cfg.Host.Principals),
		zap.Uint64("duration", cfg.Host.DurationSeconds),
		zap.String("ca-server-url", cfg.OAuth.ServerURL),
		zap.String("client-id", cfg.OAuth.ClientID),
		zap.String("token-url", cfg.OAuth.TokenURL),
	)

	p.V(logging.Verbose).Println("fetching key details")

	kType, key, err := r.KeyHandler.ReadPublicKey(ctx, cfg.Host.Key)
	if err != nil {
		return apperror.ErrFileSystem(err)
	}

	p.V(logging.VeryVerbose).Printf("found key type: %v | public key: %v\n", kType, key)
	log.Info("public key details",
		zap.String("type", kType),
		zap.String("key", key),
	)

	p.V(logging.Verbose).Println("initiating connection to OAuth")

	accessToken, err := r.OAuthClient.ClientCredentialLogin(ctx, cfg.OAuth)
	if err != nil {
		return apperror.ErrAuth(err)
	}

	p.V(logging.VeryVerbose).Println("received access token")
	log.Info("auth token received",
		zap.String("type", accessToken.TokenType),
	)

	// TODO: implement:
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file

	p.Println("[host] ok")
	return nil
}
