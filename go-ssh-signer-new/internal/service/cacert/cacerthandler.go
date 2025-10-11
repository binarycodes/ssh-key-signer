package cacert

import (
	"context"
	"os"
	"path/filepath"

	"binarycodes/ssh-keysign/internal/service"
)

const (
	defaultCertFileMode os.FileMode = 0o400
)

type CACertHandler struct{}

func (c CACertHandler) StoreUserCert(ctx context.Context, u *service.UserCertHandlerConfig) error {
	return c.writeCertForKey(u.UserConfig.Key, u.SignedResponse)
}

func (c CACertHandler) StoreHostCert(ctx context.Context, h *service.HostCertHandlerConfig) error {
	return c.writeCertForKey(h.HostConfig.Key, h.SignedResponse)
}

func (CACertHandler) writeCertForKey(keyfilePath string, s service.SignedResponse) error {
	dir := filepath.Dir(keyfilePath)
	path, err := filepath.Abs(filepath.Join(dir, s.Filename))
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(s.SignedPublicKey), defaultCertFileMode)
}
