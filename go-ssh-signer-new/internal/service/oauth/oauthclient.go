package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/mdp/qrterminal/v3"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/service"
)

type CAAuthClient struct{}

const (
	clientCredentialGrant     = "client_credentials"
	openIDScope               = "openid"
	deviceFlowLoginURLMessage = "browse to the below URL and enter the code [ %s ] to complete the login, alternatively, scan the QR code\n%s\n\n"
)

func (CAAuthClient) ClientCredentialLogin(ctx context.Context, o config.OAuth) (aToken *service.AccessToken, err error) {
	data := url.Values{}
	data.Set("client_id", o.ClientID)
	data.Set("client_secret", o.ClientSecret)
	data.Set("grant_type", clientCredentialGrant)

	req, err := http.NewRequest("POST", o.TokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	log := ctxkeys.LoggerFrom(ctx)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error(err.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, apperror.ErrHTTP(resp)
	}

	accessToken := &service.AccessToken{}
	if err := json.NewDecoder(resp.Body).Decode(accessToken); err != nil {
		return nil, err
	}

	return accessToken, nil
}

func (c CAAuthClient) DeviceFlowLogin(ctx context.Context, o config.OAuth) (aToken *service.AccessToken, err error) {
	deviceStartResponse, err := c.startDeviceFlow(ctx, o)
	if err != nil {
		return nil, err
	}

	c.showDeviceFlowLoginDetails(ctx, deviceStartResponse)

	return nil, nil
}

func (c CAAuthClient) startDeviceFlow(ctx context.Context, o config.OAuth) (aToken *service.DeviceFlowStartResponse, err error) {
	data := url.Values{}
	data.Set("client_id", o.ClientID)
	data.Set("client_secret", o.ClientSecret)
	data.Set("scope", openIDScope)

	req, err := http.NewRequest("POST", o.DeviceFlowURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	log := ctxkeys.LoggerFrom(ctx)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error(err.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, apperror.ErrHTTP(resp)
	}

	deviceFlowResponse := &service.DeviceFlowStartResponse{}
	if err := json.NewDecoder(resp.Body).Decode(deviceFlowResponse); err != nil {
		return nil, err
	}

	return deviceFlowResponse, nil
}

func (c CAAuthClient) showDeviceFlowLoginDetails(ctx context.Context, d *service.DeviceFlowStartResponse) {
	p := ctxkeys.PrinterFrom(ctx)
	p.Printf(deviceFlowLoginURLMessage, d.UserCode, d.VerificationURI)

	qrCfg := qrterminal.Config{
		Level:      qrterminal.H,
		Writer:     p.Writer,
		QuietZone:  3,
		HalfBlocks: true,
	}
	qrterminal.GenerateWithConfig(d.VerificationURIComplete, qrCfg)
}
