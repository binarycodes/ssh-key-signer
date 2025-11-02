package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"binarycodes/ssh-keysign/internal/service"
	"binarycodes/ssh-keysign/internal/service/utilities"
)

type CAKeyHandler struct{}

func (c CAKeyHandler) ReadPublicKey(ctx context.Context, path string) (keyType, pubKey string, err error) {
	p, err := utilities.NormalizePath(path)
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

func (c CAKeyHandler) NewEd25519(ctx context.Context) (*service.ED25519KeyPair, error) {
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
	if err != nil {
		return nil, err
	}

	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}

	privateKeyBytes := pem.EncodeToMemory(privBlock)

	return &service.ED25519KeyPair{
		PrivateKey:      &priv,
		PrivateKeyBytes: privateKeyBytes,
		PublicKeyString: pubKeyString,
		Type:            kType,
	}, err
}
