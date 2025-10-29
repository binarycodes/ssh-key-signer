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

	keys := &service.Keys{
		Filename:  cfg.Host.Key,
		PublicKey: key,
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
		zap.Uint64("expires_in", accessToken.ExpiresIn),
	)

	p.V(logging.Verbose).Println("initiating connection to CA server to sign public key")

	signedResponse, err := r.CertClient.IssueHostCert(ctx, &service.HostCertRequestConfig{
		HostConfig:  r.Config.Host,
		OAuthConfig: r.Config.OAuth,
		PubKey:      key,
		Token:       *accessToken,
	})
	if err != nil {
		return apperror.ErrNet(err)
	}

	p.V(logging.VeryVerbose).Println("received signed certificate")
	log.Info("signed certificate received",
		zap.String("filename", signedResponse.Filename),
	)

	p.V(logging.VeryVerbose).Println("storing the certificate")

	certSaveFilePath, err := keys.FetchCertFileName()
	if err != nil {
		return err
	}

	path, err := r.CertHandler.StoreHostCert(ctx, &service.HostCertHandlerConfig{
		CertSaveFilePath: certSaveFilePath,
		SignedResponse:   *signedResponse,
	})
	if err != nil {
		return err
	}

	p.V(logging.Normal).Printf("certificate stored at %s\n", path)
	log.Info("certificate stored",
		zap.String("filename", path),
	)

	p.V(logging.VeryVerbose).Println("done")
	return nil
}
