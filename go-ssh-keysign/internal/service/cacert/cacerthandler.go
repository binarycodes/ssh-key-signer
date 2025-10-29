package cacert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/service"
	"binarycodes/ssh-keysign/internal/service/utilities"
)

const (
	defaultCertFileMode    os.FileMode = 0o600
	defaultPrivateFileMode os.FileMode = 0o600
	defaultPublicFileMode  os.FileMode = 0o600
)

type CACertHandler struct{}

func (c CACertHandler) StoreUserCert(ctx context.Context, u *service.UserCertHandlerConfig) (path string, err error) {
	p := ctxkeys.PrinterFrom(ctx)

	if u.Keys.KeyPair != nil {
		filePrefix := fmt.Sprintf("id_%s", utilities.GenerateRandomFileName())
		userSSHDir, err := utilities.NormalizePath(constants.UserSSHDir)
		if err != nil {
			return "", err
		}

		filePathPrefix := filepath.Join(userSSHDir, filePrefix)
		if err := c.writeKeyPair(filePathPrefix, *u.Keys.KeyPair); err != nil {
			return "", err
		}

		certFilePath := fmt.Sprintf("%s-cert.pub", filePathPrefix)
		p.V(logging.Verbose).Printf("writing certificate to %s\n", certFilePath)
		return c.writeCertForKey(certFilePath, u.SignedResponse)
	}

	p.V(logging.Verbose).Printf("writing certificate to %s\n", u.CertSaveFilePath)
	return c.writeCertForKey(u.CertSaveFilePath, u.SignedResponse)
}

func (c CACertHandler) StoreHostCert(ctx context.Context, h *service.HostCertHandlerConfig) (path string, err error) {
	return c.writeCertForKey(h.CertSaveFilePath, h.SignedResponse)
}

func (CACertHandler) writeCertForKey(keyfilePath string, s service.SignedResponse) (path string, err error) {
	if err := os.WriteFile(keyfilePath, []byte(s.SignedPublicKey), defaultCertFileMode); err != nil {
		return "", apperror.ErrFileSystem(fmt.Errorf("writing cert file %q: %w", path, err))
	}

	return keyfilePath, nil
}

func (CACertHandler) writeKeyPair(privateFilePath string, k service.ED25519KeyPair) (err error) {
	publicFilePath := fmt.Sprintf("%s.pub", privateFilePath)

	if err := os.WriteFile(privateFilePath, k.PrivateKey, defaultPrivateFileMode); err != nil {
		return apperror.ErrFileSystem(fmt.Errorf("writing cert file %q: %w", privateFilePath, err))
	}

	if err := os.WriteFile(publicFilePath, []byte(k.PublicKeyString), defaultPublicFileMode); err != nil {
		return apperror.ErrFileSystem(fmt.Errorf("writing cert file %q: %w", publicFilePath, err))
	}

	return nil
}
