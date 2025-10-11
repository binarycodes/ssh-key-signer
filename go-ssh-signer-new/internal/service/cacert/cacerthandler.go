package cacert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/service"
)

const (
	defaultCertFileMode os.FileMode = 0o400
)

type CACertHandler struct{}

func (c CACertHandler) StoreUserCert(ctx context.Context, u *service.UserCertHandlerConfig) (path string, err error) {
	return c.writeCertForKey(u.UserConfig.Key, u.SignedResponse)
}

func (c CACertHandler) StoreHostCert(ctx context.Context, h *service.HostCertHandlerConfig) (path string, err error) {
	return c.writeCertForKey(h.HostConfig.Key, h.SignedResponse)
}

func (CACertHandler) writeCertForKey(keyfilePath string, s service.SignedResponse) (path string, err error) {
	dir := filepath.Dir(keyfilePath)

	path, err = filepath.Abs(filepath.Join(dir, s.Filename))
	if err != nil {
		return "", apperror.ErrFileSystem(fmt.Errorf("resolving absolute path: %w", err))
	}

	if err := os.WriteFile(path, []byte(s.SignedPublicKey), defaultCertFileMode); err != nil {
		return "", apperror.ErrFileSystem(fmt.Errorf("writing cert file %q: %w", path, err))
	}

	return path, nil
}
