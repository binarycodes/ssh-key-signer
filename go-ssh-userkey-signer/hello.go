package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
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

func main() {
	flag.Parse()

	if *hostnameFlag == "" || *keyFileFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	token := accessToken()

	if valid, message := validateKeyFile(*keyFileFlag); !valid {
		panic(message)
	}
	requestToSign(token.AccessToken, *hostnameFlag, *keyFileFlag)
}

func validateKeyFile(keyfile string) (bool, string) {

	return true, ""
}

func requestToSign(token string, hostname string, keyfile string) {
	log.Printf("attempt to sign the key in file '%v' for hostname '%v'", keyfile, hostname)
}

func accessToken() AccessToken {
	// form data
	data := url.Values{}
	data.Set("client_id", "my-test-client")
	data.Set("client_secret", "UTRtYkyYN1nbgdPPbBru1FDVsE8ye5JE")
	data.Set("grant_type", "client_credentials")

	postUrl := "http://localhost:8090/realms/my-test-realm/protocol/openid-connect/token"
	req, err := http.NewRequest("POST", postUrl, bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(resp.Status)
	}

	accessToken := &AccessToken{}
	if err := json.NewDecoder(resp.Body).Decode(accessToken); err != nil {
		panic(err)
	}

	if accessToken.AccessToken != "" {
		log.Println("access token received")
	}

	return *accessToken
}
