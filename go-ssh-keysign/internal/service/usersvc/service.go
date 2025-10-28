package usersvc

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/service"
)

type UserService struct{}

type keys struct {
	PublicKey string
	KeyPair   *service.ED25519KeyPair
}

func (k keys) getPublicKey(u config.User) string {
	if u.Key != "" {
		return k.PublicKey
	}

	return k.KeyPair.PublicKeyString
}

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

	key, err := u.fetchKeys(ctx, r)
	if err != nil {
		return err
	}

	accessToken, err := u.fetchAccessToken(ctx, r)
	if err != nil {
		return err
	}

	signedResponse, err := u.certSignRequest(ctx, r, key, accessToken)
	if err != nil {
		return err
	}

	p.V(logging.VeryVerbose).Println("storing the certificate")

	path, err := r.CertHandler.StoreUserCert(ctx, &service.UserCertHandlerConfig{
		UserConfig:     cfg.User,
		SignedResponse: *signedResponse,
	})
	if err != nil {
		return err
	}

	p.V(logging.Normal).Printf("certificate stored at %s", path)
	log.Info("certificate stored",
		zap.String("filename", path),
	)

	p.V(logging.VeryVerbose).Println("done")
	return nil
}

func (UserService) fetchKeys(ctx context.Context, r *service.Runner) (*keys, error) {
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

		return &keys{
			PublicKey: key,
			KeyPair:   nil,
		}, nil
	}

	keyPair, err := r.KeyHandler.NewEd25519()
	if err != nil {
		return nil, err
	}

	p.V(logging.VeryVerbose).Printf("created key type: %v | public key: %v\n", keyPair.Type, keyPair.PublicKeyString)
	log.Info("public key details",
		zap.String("type", keyPair.Type),
		zap.String("key", keyPair.PublicKeyString),
	)

	return &keys{
		PublicKey: "",
		KeyPair:   keyPair,
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

func (UserService) certSignRequest(ctx context.Context, r *service.Runner, k *keys, token *service.AccessToken) (certResp *service.SignedResponse, err error) {
	log := ctxkeys.LoggerFrom(ctx)
	p := ctxkeys.PrinterFrom(ctx)
	cfg := r.Config

	p.V(logging.Verbose).Println("initiating connection to CA server to sign public key")

	signedResponse, err := r.CertClient.IssueUserCert(ctx, &service.UserCertRequestConfig{
		UserConfig:  cfg.User,
		OAuthConfig: cfg.OAuth,
		PubKey:      k.getPublicKey(cfg.User),
		Token:       *token,
	})
	if err != nil {
		return nil, apperror.ErrNet(err)
	}

	p.V(logging.VeryVerbose).Println("received signed certificate")
	log.Info("signed certificate received",
		zap.String("filename", signedResponse.Filename),
	)

	return signedResponse, nil
}
