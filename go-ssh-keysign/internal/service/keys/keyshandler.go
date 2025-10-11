package keys

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type CAKeyHandler struct{}

func expandPath(p string) (string, error) {
	path := p

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if trimmed, found := strings.CutPrefix(p, "~"); found {
		return filepath.Join(home, trimmed), nil
	}

	if trimmed, found := strings.CutPrefix(p, "$HOME"); found {
		return filepath.Join(home, trimmed), nil
	}

	/* allow expansion of other environment variables */
	return os.ExpandEnv(path), nil
}

func (CAKeyHandler) ReadPublicKey(ctx context.Context, path string) (keyType, pubKey string, err error) {
	p, err := expandPath(path)
	if err != nil {
		return "", "", err
	}

	b, err := os.ReadFile(p)
	if err != nil {
		return "", "", err
	}
	return parsePublicKey(b)
}

func parsePublicKey(pub []byte) (keyType, pubKey string, err error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		return "", "", err
	}

	pubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	return pk.Type(), pubKeyStr, nil
}

func (CAKeyHandler) WriteAtomic(path string, data []byte, perm uint32) error { return nil }
func (CAKeyHandler) BackupIfExists(path string) error                        { return nil }
