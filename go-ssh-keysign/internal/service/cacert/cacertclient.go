package cacert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/config"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/service"
)

type CACertClient struct{}

func (CACertClient) hostSignURL(cfg config.OAuth) string {
	return fmt.Sprintf("%s/rest/key/hostSign", cfg.ServerURL)
}

func (CACertClient) userSignURL(cfg config.OAuth) string {
	return fmt.Sprintf("%s/rest/key/userSign", cfg.ServerURL)
}

func (c CACertClient) IssueUserCert(ctx context.Context, u *service.UserCertRequestConfig) (*service.SignedResponse, error) {
	signRequest := service.SignRequest{
		Filename:  filepath.Base(u.UserConfig.Key),
		PublicKey: u.PubKey,
		Hostname:  u.UserConfig.Principals[0],
	}

	postBody := new(bytes.Buffer)
	if err := json.NewEncoder(postBody).Encode(signRequest); err != nil {
		return nil, apperror.ErrNet(err)
	}

	req, err := http.NewRequest("POST", c.userSignURL(u.OAuthConfig), postBody)
	if err != nil {
		return nil, apperror.ErrNet(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", u.Token.AccessToken))

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, apperror.ErrNet(err)
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

	signedResponse := &service.SignedResponse{}
	if err := json.NewDecoder(resp.Body).Decode(signedResponse); err != nil {
		return nil, apperror.ErrNet(err)
	}

	return signedResponse, nil
}

func (c CACertClient) IssueHostCert(ctx context.Context, h *service.HostCertRequestConfig) (*service.SignedResponse, error) {
	signRequest := service.SignRequest{
		Filename:  filepath.Base(h.HostConfig.Key),
		PublicKey: h.PubKey,
		Hostname:  h.HostConfig.Principals[0],
	}

	postBody := new(bytes.Buffer)
	if err := json.NewEncoder(postBody).Encode(signRequest); err != nil {
		return nil, apperror.ErrNet(err)
	}

	req, err := http.NewRequest("POST", c.hostSignURL(h.OAuthConfig), postBody)
	if err != nil {
		return nil, apperror.ErrNet(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", h.Token.AccessToken))

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, apperror.ErrNet(err)
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

	signedResponse := &service.SignedResponse{}
	if err := json.NewDecoder(resp.Body).Decode(signedResponse); err != nil {
		return nil, apperror.ErrNet(err)
	}

	return signedResponse, nil
}
