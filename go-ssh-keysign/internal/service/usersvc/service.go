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

func (u UserService) SignUserKey(ctx context.Context, r *service.Runner) error {
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

	keys, err := u.fetchKeys(ctx, r)
	if err != nil {
		return err
	}

	accessToken, err := u.fetchAccessToken(ctx, r)
	if err != nil {
		return err
	}

	signedResponse, err := u.certSignRequest(ctx, r, keys, accessToken)
	if err != nil {
		return err
	}

	if err := u.storeCertificate(ctx, r, keys, signedResponse); err != nil {
		return err
	}

	p.V(logging.VeryVerbose).Println("done")
	return nil
}

func (UserService) fetchKeys(ctx context.Context, r *service.Runner) (*service.Keys, error) {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)
	cfg := r.Config

	p.V(logging.Verbose).Println("fetching key details")

	if cfg.User.Key != "" {
		kType, key, err := r.KeyHandler.ReadPublicKey(ctx, cfg.User.Key)
		if err != nil {
			return nil, err
		}

		p.V(logging.VeryVerbose).Printf("found key type: %v | public key: %v\n", kType, key)
		log.Info("public key details",
			zap.String("type", kType),
			zap.String("key", key),
		)

		return &service.Keys{
			Filename:  cfg.User.Key,
			PublicKey: key,
		}, nil
	}

	keyPair, err := r.KeyHandler.NewEd25519(ctx)
	if err != nil {
		return nil, err
	}

	p.V(logging.VeryVerbose).Printf("created key type: %v | public key: %v\n", keyPair.Type, keyPair.PublicKeyString)
	log.Info("public key details",
		zap.String("type", keyPair.Type),
		zap.String("key", keyPair.PublicKeyString),
	)

	return &service.Keys{
		KeyPair: keyPair,
	}, nil
}

func (UserService) fetchAccessToken(ctx context.Context, r *service.Runner) (token *service.AccessToken, err error) {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)
	cfg := r.Config

	p.V(logging.Verbose).Println("initiating connection to OAuth")

	var accessToken *service.AccessToken

	if cfg.OAuth.HasClientCredential() {
		p.V(logging.Verbose).Println("using client credential")
		accessToken, err = r.OAuthClient.ClientCredentialLogin(ctx, cfg.OAuth)
		if err != nil {
			return nil, apperror.ErrAuth(err)
		}
	} else {
		p.V(logging.Verbose).Println("using device flow")
		accessToken, err = r.OAuthClient.DeviceFlowLogin(ctx, cfg.OAuth)
		if err != nil {
			return nil, apperror.ErrAuth(err)
		}
	}

	if accessToken == nil || !accessToken.OK(ctx) {
		return nil, apperror.ErrAuth(errors.New("failed to retrieve access token"))
	}

	p.V(logging.VeryVerbose).Println("received access token")
	log.Info("auth token received",
		zap.String("type", accessToken.TokenType),
		zap.Uint64("expires_in", accessToken.ExpiresIn),
	)

	return accessToken, nil
}

func (UserService) certSignRequest(ctx context.Context, r *service.Runner, k *service.Keys, token *service.AccessToken) (certResp *service.SignedResponse, err error) {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)
	cfg := r.Config

	p.V(logging.Verbose).Println("initiating connection to CA server to sign public key")

	signedResponse, err := r.CertClient.IssueUserCert(ctx, &service.UserCertRequestConfig{
		UserConfig:  cfg.User,
		OAuthConfig: cfg.OAuth,
		PubKey:      k.FetchPublicKey(),
		Token:       *token,
	})
	if err != nil {
		return nil, apperror.ErrNet(err)
	}

	p.V(logging.VeryVerbose).Println("received signed certificate")
	log.Info("signed certificate received")

	return signedResponse, nil
}

func (UserService) storeCertificate(ctx context.Context, r *service.Runner, k *service.Keys, s *service.SignedResponse) (err error) {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)

	p.V(logging.VeryVerbose).Println("storing the certificate")

	agent, path, err := r.CertHandler.StoreUserCertFile(ctx, &service.UserCertHandlerConfig{
		Keys:           *k,
		SignedResponse: *s,
	})
	if err != nil {
		return err
	}

	if agent {
		p.V(logging.Normal).Println("certificate stored in ssh-agent")
	} else {
		p.V(logging.Normal).Printf("certificate stored at %s\n", path)
	}

	log.Info("certificate stored",
		zap.Bool("agent", agent),
		zap.String("filename", path),
	)

	return nil
}
