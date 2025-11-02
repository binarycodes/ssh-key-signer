package service

import (
	"context"
	"crypto/ed25519"

	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/service/utilities"
)

type KeyHandler interface {
	ReadPublicKey(ctx context.Context, path string) (keyType, pubKey string, err error)
	NewEd25519(ctx context.Context) (*ED25519KeyPair, error)
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
	StoreUserCertFile(ctx context.Context, u *UserCertHandlerConfig) (agent bool, path string, err error)
	StoreUserCertAgent(ctx context.Context, u *UserCertHandlerConfig) error
	StoreHostCertFile(ctx context.Context, h *HostCertHandlerConfig) (path string, err error)
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
	Keys           Keys
	SignedResponse SignedResponse
}

type HostCertHandlerConfig struct {
	CertSaveFilePath string
	SignedResponse   SignedResponse
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
	PublicKey string `json:"publicKey"`
	Principal string `json:"principal"`
}

type SignedResponse struct {
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

type ED25519KeyPair struct {
	PrivateKey      *ed25519.PrivateKey
	PrivateKeyBytes []byte
	PublicKeyString string
	Type            string
}

type Keys struct {
	Filename  string
	PublicKey string
	KeyPair   *ED25519KeyPair
}

func (k Keys) FetchPublicKey() string {
	if k.Filename != "" {
		return k.PublicKey
	}

	return k.KeyPair.PublicKeyString
}

func (k Keys) FetchCertFileName() (string, error) {
	if k.Filename != "" {
		return utilities.GetCertificateFilePath(k.Filename)
	}

	return "", nil
}
