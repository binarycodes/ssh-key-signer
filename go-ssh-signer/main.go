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

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

const (
	clientCredentialGrant = "client_credentials"
)

var (
	version        = "undefined"
	configPaths    = [2]string{"/etc/ssh-keysigner/config.yml", "config.yml"}
	configPathFlag = flag.String("config", "", "path of the config file")
	hostnameFlag   = flag.String("hostname", "", "specify the hostname for the certificate")
	keyFileFlag    = flag.String("keyfile", "", "path of the key file that is to be signed")
	versionFlag    = flag.Bool("version", false, "display version")
	config         Config
)

type CaRequestURL interface {
	hostSignURL() string
	userSignURL() string
}

type Config struct {
	CaServerURL  string `mapstructure:"ca_server_url"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	TokenURL     string `mapstructure:"token_url"`
}

func (config Config) hostSignURL() string {
	return fmt.Sprintf("%v/rest/key/hostSign", config.CaServerURL)
}

func (config Config) userSignURL() string {
	return fmt.Sprintf("%v/rest/key/userSign", config.CaServerURL)
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

func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}

	if *hostnameFlag == "" || *keyFileFlag == "" {
		_, _ = fmt.Fprintln(os.Stderr, "Error: -hostname and -keyfile flag is required")
		flag.Usage()
		os.Exit(1)
	}

	config = loadConfig()

	token := accessToken()
	requestToSign(token.AccessToken, *hostnameFlag, *keyFileFlag)
}

func loadConfig() Config {
	var file = readConfig()

	if file == nil {
		exitWithError(errors.New("no config file found"))
	}

	var config Config
	var raw interface{}

	// unmarshal our input YAML file into empty interface
	if err := yaml.Unmarshal(file, &raw); err != nil {
		exitWithError(err)
	}

	decoder, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{WeaklyTypedInput: true, Result: &config})
	if err := decoder.Decode(raw); err != nil {
		exitWithError(err)
	}

	return config
}

func readConfig() []byte {
	var file []byte
	var err error

	if *configPathFlag != "" {
		file, err = os.ReadFile(*configPathFlag)
		if err != nil {
			log.Fatalf("Error reading config file: %v - %v", *configPathFlag, err)
		}
	} else {
		for _, configPath := range configPaths {
			file, err = os.ReadFile(configPath)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "config not found at %v\n", configPath)
			} else {
				break
			}
		}
	}

	return file
}

func readKeyFile(keyfile string) (string, error) {
	keyfilePath := strings.TrimSpace(keyfile)

	extension := filepath.Ext(keyfilePath)
	if extension != ".pub" {
		return "", errors.New("only public key files are expected here. [Hint: name ending in .pub]")
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

	req, err := http.NewRequest("POST", config.hostSignURL(), postBody)
	if err != nil {
		exitWithError(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token))

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		exitWithError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		exitForHTTPErrorResponse(*resp)
	}

	signedResponse := &SignedResponse{}
	if err := json.NewDecoder(resp.Body).Decode(signedResponse); err != nil {
		exitWithError(err)
	}

	if err := saveSignedResponse(keyfile, *signedResponse); err != nil {
		exitWithError(err)
	}

	log.Printf("cert signed successfully")
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
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("grant_type", clientCredentialGrant)

	req, err := http.NewRequest("POST", config.TokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		exitWithError(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		exitWithError(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		exitForHTTPErrorResponse(*resp)
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
	log.Fatalf("Exit for ERROR :: %v\n", err.Error())
}

func exitForHTTPErrorResponse(resp http.Response) {
	body, err := io.ReadAll(resp.Body)
	log.Printf("HTTP status :: %v\n", resp.Status)
	if err != nil {
		exitWithError(err)
	}
	exitWithError(errors.New(string(body)))
}
