package service

import "context"

type KeyHandler interface {
	ReadPublicKey(ctx context.Context, path string) ([]byte, error)
	ParseAuthorizedKey(pub []byte) (algo, comment string, err error)
	WriteAtomic(path string, data []byte, perm uint32) error
	BackupIfExists(path string) error
}

type CertClient interface {
	IssueUserCert(ctx context.Context, pubKey []byte, principals []string, durationSec uint64) ([]byte, error)
	IssueHostCert(ctx context.Context, pubKey []byte, principals []string, durationSec uint64) ([]byte, error)
}
