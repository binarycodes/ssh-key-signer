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

type OAuthClient interface {
	ClientCredentialLogin(ctx context.Context, oauth config.OAuth) (aToken *AccessToken, err error)
}

type Runner struct {
	KeyHandler  KeyHandler
	OAuthClient OAuthClient
	CertClient  CertClient
	Config      config.Config
}

type AccessToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
}
