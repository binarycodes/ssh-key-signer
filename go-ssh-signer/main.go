package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var (
	hostnameFlag = flag.String("hostname", "", "specify the hostname for the certificate")
	keyFileFlag  = flag.String("keyfile", "", "path of the key file that is to be signed")
)

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
	Hostname  string `json:"data"`
}

type SignedResponse struct {
	Filename        string `json:"filename"`
	SignedPublicKey string `json:"signedKey"`
}

func main() {
	flag.Parse()

	if *hostnameFlag == "" || *keyFileFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	token := accessToken()
	requestToSign(token.AccessToken, *hostnameFlag, *keyFileFlag)
}

func readKeyFile(keyfile string) (string, error) {
	keyfilePath := strings.TrimSpace(keyfile)

	ext := filepath.Ext(keyfilePath)
	if ext != ".pub" {
		return "", errors.New("Only public key files are expected here. [Hint: name ending in .pub]")
	}

	if _, err := os.Stat(keyfilePath); err != nil {
		return "", err
	}

	data, err := os.ReadFile(keyfilePath)
	if err != nil {
		exitWithError(err)
	}

	return string(data), nil
}

func requestToSign(token string, hostname string, keyfile string) {
	log.Printf("attempt to sign the key for hostname '%v'", hostname)

	publicKey, err := readKeyFile(keyfile)
	if err != nil {
		exitWithError(err)
	}

	signRequest := SignRequest{
		Filename:  filepath.Base(keyfile),
		PublicKey: publicKey,
		Hostname:  hostname,
	}

	postBody := new(bytes.Buffer)
	if err := json.NewEncoder(postBody).Encode(signRequest); err != nil {
		exitWithError(err)
	}

	postUrl := "http://localhost:8088/rest/key/hostSign"
	req, err := http.NewRequest("POST", postUrl, postBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		exitWithError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		exitForHttpErrorResponse(*resp)
	}

	signedResponse := &SignedResponse{}
	if err := json.NewDecoder(resp.Body).Decode(signedResponse); err != nil {
		exitWithError(err)
	}

	if err := saveSignedResponse(keyfile, *signedResponse); err != nil {
		exitWithError(err)
	}
}

func saveSignedResponse(keyfile string, signedResponse SignedResponse) error {
	dir := filepath.Dir(keyfile)
	certFileAbsolutePath, err := filepath.Abs(dir + "/" + signedResponse.Filename)
	if err != nil {
		exitWithError(err)
	}
	return os.WriteFile(certFileAbsolutePath, []byte(signedResponse.SignedPublicKey), 0400)
}

func accessToken() AccessToken {
	// form data
	data := url.Values{}
	data.Set("client_id", "my-test-client")
	data.Set("client_secret", "UTRtYkyYN1nbgdPPbBru1FDVsE8ye5JE")
	data.Set("grant_type", "client_credentials")

	postUrl := "http://10.88.0.100:8090/realms/my-test-realm/protocol/openid-connect/token"
	req, err := http.NewRequest("POST", postUrl, bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		exitWithError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		exitForHttpErrorResponse(*resp)
	}

	accessToken := &AccessToken{}
	if err := json.NewDecoder(resp.Body).Decode(accessToken); err != nil {
		exitWithError(err)
	}

	if accessToken.AccessToken != "" {
		log.Println("access token received")
	}

	return *accessToken
}

func exitWithError(err error) {
	fmt.Fprintf(os.Stderr, "Exit for ERROR :: %v\n", err.Error())
	os.Exit(1)
}

func exitForHttpErrorResponse(resp http.Response) {
	body, err := io.ReadAll(resp.Body)
	fmt.Fprintf(os.Stderr, "HTTP status :: %v\n", resp.Status)
	if err != nil {
		exitWithError(err)
	}
	exitWithError(errors.New(string(body)))
}
