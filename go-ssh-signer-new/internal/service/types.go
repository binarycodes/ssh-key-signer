package service

import (
	"context"

	"binarycodes/ssh-keysign/internal/config"
)

type KeyHandler interface {
	ReadPublicKey(ctx context.Context, path string) (keyType, pubKey string, err error)
	WriteAtomic(path string, data []byte, perm uint32) error
	BackupIfExists(path string) error
}

type CertClient interface {
	IssueUserCert(ctx context.Context, pubKey []byte, principals []string, durationSec uint64) ([]byte, error)
	IssueHostCert(ctx context.Context, pubKey []byte, principals []string, durationSec uint64) ([]byte, error)
}

type Runner struct {
	KHandler KeyHandler
	CClient  CertClient
	Config   config.Config
}
