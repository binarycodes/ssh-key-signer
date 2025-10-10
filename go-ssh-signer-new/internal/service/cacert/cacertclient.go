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

func (c CACertClient) IssueUserCert(ctx context.Context, u config.User, o config.OAuth, pubKey string, token service.AccessToken) (*service.SignedResponse, error) {
	signRequest := service.SignRequest{
		Filename:  filepath.Base(u.Key),
		PublicKey: pubKey,
		Hostname:  u.Principals[0],
	}

	postBody := new(bytes.Buffer)
	if err := json.NewEncoder(postBody).Encode(signRequest); err != nil {
		return nil, apperror.ErrNet(err)
	}

	req, err := http.NewRequest("POST", c.userSignURL(o), postBody)
	if err != nil {
		return nil, apperror.ErrNet(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token.AccessToken))

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

func (c CACertClient) IssueHostCert(ctx context.Context, h config.Host, o config.OAuth, pubKey string, token service.AccessToken) (*service.SignedResponse, error) {
	signRequest := service.SignRequest{
		Filename:  filepath.Base(h.Key),
		PublicKey: pubKey,
		Hostname:  h.Principals[0],
	}

	postBody := new(bytes.Buffer)
	if err := json.NewEncoder(postBody).Encode(signRequest); err != nil {
		return nil, apperror.ErrNet(err)
	}

	req, err := http.NewRequest("POST", c.hostSignURL(o), postBody)
	if err != nil {
		return nil, apperror.ErrNet(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

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
