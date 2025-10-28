package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"binarycodes/ssh-keysign/internal/service"
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

func (c CAKeyHandler) ReadPublicKey(ctx context.Context, path string) (keyType, pubKey string, err error) {
	p, err := expandPath(path)
	if err != nil {
		return "", "", err
	}

	b, err := os.ReadFile(p)
	if err != nil {
		return "", "", err
	}
	return c.parsePublicKey(b)
}

func (CAKeyHandler) parsePublicKey(pub []byte) (keyType, pubKey string, err error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		return "", "", err
	}

	pubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	return pk.Type(), pubKeyStr, nil
}

func (c CAKeyHandler) NewEd25519() (*service.ED25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubKeyMarshalled := string(ssh.MarshalAuthorizedKey(sshPubKey))
	kType, pubKeyString, err := c.parsePublicKey([]byte(pubKeyMarshalled))

	return &service.ED25519KeyPair{
		PrivateKey:      priv,
		PublicKey:       pub,
		PublicKeyString: pubKeyString,
		Type:            kType,
	}, err
}
