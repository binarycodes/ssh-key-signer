package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/mdp/qrterminal/v3"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/service"
)

type CAAuthClient struct{}

const (
	clientCredentialGrant     = "client_credentials"
	deviceGrant               = "urn:ietf:params:oauth:grant-type:device_code"
	openIDScope               = "openid"
	deviceFlowLoginURLMessage = "browse to the below URL and enter the code [ %s ] to complete the login, alternatively, scan the QR code\n%s\n\n"
)

type AuthPendingError struct {
	ErrorType        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type backoffConfig struct {
	InitialDelay   time.Duration // starting delay when server gives no interval
	MaxDelay       time.Duration // cap each sleep
	MaxElapsedTime time.Duration // overall timeout
	Factor         float64       // e.g. 2.0 for exponential
}

func DefaultBackoffConfig() backoffConfig {
	return backoffConfig{
		InitialDelay:   2 * time.Second,
		MaxDelay:       30 * time.Second,
		MaxElapsedTime: 2 * time.Minute,
		Factor:         2.0,
	}
}

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

	backoffConfig := DefaultBackoffConfig()
	aToken, err = c.retryPollForAuthToken(ctx, o, deviceStartResponse, backoffConfig)
	if err != nil {
		return nil, err
	}

	return aToken, nil
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

func (c CAAuthClient) pollForAuthToken(ctx context.Context, o config.OAuth, d *service.DeviceFlowStartResponse) (token *service.AccessToken, retry bool, err error) {
	data := url.Values{}
	data.Set("client_id", o.ClientID)
	data.Set("client_secret", o.ClientSecret)
	data.Set("grant_type", deviceGrant)
	data.Set("device_code", d.DeviceCode)

	req, err := http.NewRequest("POST", o.TokenPollURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, false, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}

	log := ctxkeys.LoggerFrom(ctx)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error(err.Error())
		}
	}()

	p := ctxkeys.PrinterFrom(ctx)
	if resp.StatusCode == http.StatusBadRequest {
		authPendingError := &AuthPendingError{}
		if err := json.NewDecoder(resp.Body).Decode(authPendingError); err != nil {
			return nil, false, err
		}
		p.V(logging.VeryVerbose).Printf("%s\n", authPendingError.ErrorDescription)
		return nil, true, apperror.ErrAuth(errors.New(authPendingError.ErrorDescription))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, apperror.ErrHTTP(resp)
	}

	accessToken := &service.AccessToken{}
	if err := json.NewDecoder(resp.Body).Decode(accessToken); err != nil {
		return nil, false, err
	}

	return accessToken, false, nil
}

func (c CAAuthClient) retryPollForAuthToken(ctx context.Context, o config.OAuth, d *service.DeviceFlowStartResponse, bcfg backoffConfig) (*service.AccessToken, error) {
	start := time.Now()
	delay := max(bcfg.InitialDelay, time.Duration(d.Interval)*time.Second)

	bcfg.MaxElapsedTime = min(bcfg.MaxElapsedTime, time.Duration(d.ExpiresIn)*time.Second)
	bcfg.MaxDelay = max(bcfg.MaxDelay, time.Duration(d.Interval)*time.Second)

	// first attempt happens immediately
	aToken, retry, err := c.pollForAuthToken(ctx, o, d)
	if err == nil {
		return aToken, nil
	}

	if !retry {
		return nil, err
	}

	for {
		if bcfg.MaxElapsedTime > 0 && time.Since(start) >= bcfg.MaxElapsedTime {
			return nil, apperror.ErrAuth(fmt.Errorf("timeout waiting for auth token after %s: %w", time.Since(start), err))
		}

		sleep := delay

		if bcfg.MaxDelay > 0 && sleep > bcfg.MaxDelay {
			sleep = bcfg.MaxDelay
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}

		// try again
		aToken, retry, err = c.pollForAuthToken(ctx, o, d)
		if err == nil {
			return aToken, nil
		}

		if !retry {
			return nil, err
		}

		// include delay factor for next round
		if bcfg.Factor > 1 {
			next := time.Duration(float64(delay) * bcfg.Factor)
			if bcfg.MaxDelay > 0 && next > bcfg.MaxDelay {
				next = bcfg.MaxDelay
			}
			delay = next
		}
	}
}
