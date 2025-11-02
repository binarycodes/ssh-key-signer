package cacert

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/service"
)

const (
	defaultCertFileMode    os.FileMode = 0o600
	defaultPrivateFileMode os.FileMode = 0o600
	defaultPublicFileMode  os.FileMode = 0o600
)

type CACertHandler struct{}

func (c CACertHandler) StoreUserCertFile(ctx context.Context, u *service.UserCertHandlerConfig) (agentmode bool, path string, err error) {
	p := ctxkeys.PrinterFrom(ctx)

	if u.Keys.KeyPair != nil {
		p.V(logging.Verbose).Println("writing certificate to ssh agent")

		if err := c.StoreUserCertAgent(ctx, u); err != nil {
			return true, "", err
		}

		return true, "", nil
	}

	certSaveFilePath, err := u.Keys.FetchCertFileName()
	if err != nil {
		return false, "", err
	}

	p.V(logging.Verbose).Printf("writing certificate to %s\n", certSaveFilePath)

	path, err = c.writeCertForKey(certSaveFilePath, u.SignedResponse)
	return false, path, err
}

func (c CACertHandler) StoreHostCertFile(ctx context.Context, h *service.HostCertHandlerConfig) (path string, err error) {
	return c.writeCertForKey(h.CertSaveFilePath, h.SignedResponse)
}

func (CACertHandler) writeCertForKey(keyfilePath string, s service.SignedResponse) (path string, err error) {
	if err := os.WriteFile(keyfilePath, []byte(s.SignedPublicKey), defaultCertFileMode); err != nil {
		return "", apperror.ErrFileSystem(fmt.Errorf("writing cert file %q: %w", path, err))
	}

	return keyfilePath, nil
}

func (CACertHandler) StoreKeyPair(privateFilePath string, k service.ED25519KeyPair) (err error) {
	publicFilePath := fmt.Sprintf("%s.pub", privateFilePath)

	if err := os.WriteFile(privateFilePath, k.PrivateKeyBytes, defaultPrivateFileMode); err != nil {
		return apperror.ErrFileSystem(fmt.Errorf("writing cert file %q: %w", privateFilePath, err))
	}

	if err := os.WriteFile(publicFilePath, []byte(k.PublicKeyString), defaultPublicFileMode); err != nil {
		return apperror.ErrFileSystem(fmt.Errorf("writing cert file %q: %w", publicFilePath, err))
	}

	return nil
}

func (CACertHandler) StoreUserCertAgent(ctx context.Context, u *service.UserCertHandlerConfig) error {
	log := ctxkeys.LoggerFrom(ctx)

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return errors.New("SSH_AUTH_SOCK not set; is ssh-agent running?")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("connect to ssh-agent: %w", err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			log.Error(err.Error())
		}
	}()

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(u.SignedResponse.SignedPublicKey))
	if err != nil {
		return apperror.ErrCert(fmt.Errorf("parse user certificate: %w", err))
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.New("provided blob is not an ssh Certificate")
	}

	lifetime := constants.DefaultDurationForUserKey()

	now := uint64(time.Now().Unix())
	if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore > now {
		certDuration := uint64(time.Duration(cert.ValidBefore-now) * time.Second)
		lifetime = min(lifetime, certDuration)
	}

	add := agent.AddedKey{
		PrivateKey:       u.Keys.KeyPair.PrivateKey,
		Certificate:      cert,
		Comment:          time.Now().String(),
		LifetimeSecs:     uint32(lifetime),
		ConfirmBeforeUse: constants.ConfirmCertBeforeUse,
	}

	ag := agent.NewClient(conn)
	if err := ag.Add(add); err != nil {
		return fmt.Errorf("add key+cert to ssh-agent: %w", err)
	}

	return nil
}
