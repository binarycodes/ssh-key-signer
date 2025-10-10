package usersvc

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/apperror"
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

	var accessToken *service.AccessToken

	if cfg.OAuth.HasClientCredential() {
		accessToken, err = r.OAuthClient.ClientCredentialLogin(ctx, cfg.OAuth)
		if err != nil {
			return apperror.ErrAuth(err)
		}
	} else {
		accessToken, err = r.OAuthClient.DeviceFlowLogin(ctx, cfg.OAuth)
		if err != nil {
			return apperror.ErrAuth(err)
		}
	}

	if accessToken == nil {
		return apperror.ErrAuth(errors.New("failed to retrieve access token"))
	}

	p.V(logging.VeryVerbose).Println("received access token")
	log.Info("auth token received",
		zap.String("type", accessToken.TokenType),
		zap.Int64("expires_in", accessToken.ExpiresIn),
	)

	p.V(logging.Verbose).Println("initiating connection to CA server to sign public key")

	signedResponse, err := r.CertClient.IssueUserCert(ctx, r.Config.User, r.Config.OAuth, key, *accessToken)
	if err != nil {
		return apperror.ErrNet(err)
	}

	p.V(logging.VeryVerbose).Println("received signed certificate")
	log.Info("signed certificate received",
		zap.String("filename", signedResponse.Filename),
	)

	// TODO: implement:
	// 1) read public key at o.Key
	// 2) request token using o.ClientID/o.Secret against o.TokenURL
	// 3) call o.CAServer to sign host cert with principals + duration
	// 4) write cert to stdout/file
	p.Println("[user] ok")
	return nil
}
