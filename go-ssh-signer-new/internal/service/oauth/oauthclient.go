package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/service"
)

type CAAuthClient struct{}

const (
	clientCredentialGrant = "client_credentials"
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
