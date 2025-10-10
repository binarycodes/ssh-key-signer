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
	IssueUserCert(ctx context.Context, u config.User, o config.OAuth, pubKey string, token AccessToken) (*SignedResponse, error)
	IssueHostCert(ctx context.Context, h config.Host, o config.OAuth, pubKey string, token AccessToken) (*SignedResponse, error)
}

type OAuthClient interface {
	ClientCredentialLogin(ctx context.Context, oauth config.OAuth) (aToken *AccessToken, err error)
	DeviceFlowLogin(ctx context.Context, oauth config.OAuth) (aToken *AccessToken, err error)
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

type SignRequest struct {
	Filename  string `json:"filename"`
	PublicKey string `json:"publicKey"`
	Hostname  string `json:"principal"`
}

type SignedResponse struct {
	Filename        string `json:"filename"`
	SignedPublicKey string `json:"signedKey"`
}
