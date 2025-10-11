package service

import (
	"context"

	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
)

type KeyHandler interface {
	ReadPublicKey(ctx context.Context, path string) (keyType, pubKey string, err error)
	WriteAtomic(path string, data []byte, perm uint32) error
	BackupIfExists(path string) error
}

type CertClient interface {
	IssueUserCert(ctx context.Context, u *UserCertRequestConfig) (*SignedResponse, error)
	IssueHostCert(ctx context.Context, h *HostCertRequestConfig) (*SignedResponse, error)
}

type OAuthClient interface {
	ClientCredentialLogin(ctx context.Context, oauth config.OAuth) (aToken *AccessToken, err error)
	DeviceFlowLogin(ctx context.Context, oauth config.OAuth) (aToken *AccessToken, err error)
}

type CertHandler interface {
	StoreUserCert(ctx context.Context, u *UserCertHandlerConfig) (path string, err error)
	StoreHostCert(ctx context.Context, h *HostCertHandlerConfig) (path string, err error)
}

type UserCertRequestConfig struct {
	UserConfig  config.User
	OAuthConfig config.OAuth
	PubKey      string
	Token       AccessToken
}

type HostCertRequestConfig struct {
	HostConfig  config.Host
	OAuthConfig config.OAuth
	PubKey      string
	Token       AccessToken
}

type UserCertHandlerConfig struct {
	UserConfig     config.User
	SignedResponse SignedResponse
}

type HostCertHandlerConfig struct {
	HostConfig     config.Host
	SignedResponse SignedResponse
}

type Runner struct {
	Config      config.Config
	KeyHandler  KeyHandler
	OAuthClient OAuthClient
	CertClient  CertClient
	CertHandler CertHandler
}

type AccessToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        uint64 `json:"expires_in"`
	RefreshExpiresIn uint64 `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
}

func (a AccessToken) OK(ctx context.Context) bool {
	p := ctxkeys.PrinterFrom(ctx)

	if len(a.AccessToken) > 10 {
		p.V(logging.VeryVerbose).Printf("accessToken: %v\n", a.AccessToken[:10]+"...")
	} else {
		p.V(logging.VeryVerbose).Printf("accessToken: %v\n", a.AccessToken)
	}

	p.V(logging.VeryVerbose).Printf("expiresIn: %v\n", a.ExpiresIn)
	p.V(logging.VeryVerbose).Printf("tokenType: %v\n", a.TokenType)
	p.V(logging.VeryVerbose).Printf("scope: %v\n", a.Scope)

	return a.AccessToken != "" && a.ExpiresIn > 0 && a.TokenType != "" && a.Scope != ""
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

type DeviceFlowStartResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               uint64 `json:"expires_in"`
	Interval                uint64 `json:"interval"`
}
