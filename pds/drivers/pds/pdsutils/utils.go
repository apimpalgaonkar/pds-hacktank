package pds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	pds "github.com/portworx/pds-api-go-client/pds/v1alpha1"
	log "github.com/sirupsen/logrus"
)

// BearerToken struct
type BearerToken struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint64 `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

const (
	envControlPlaneURL    = "CONTROL_PLANE_URL"
	envPDSTestAccountName = "TEST_ACCOUNT_NAME"
	envTargetKubeconfig   = "TARGET_KUBECONFIG"
	envUsername           = "PDS_USERNAME"
	envPassword           = "PDS_PASSWORD"
	envPDSClientSecret    = "PDS_CLIENT_SECRET"
	envPDSClientID        = "PDS_CLIENT_ID"
	envPDSISSUERURL       = "PDS_ISSUER_URL"
	envClusterType        = "CLUSTER_TYPE"
)

// Environment lhasha
type Environment struct {
	PDSControlPlaneURL   string
	PDSTestAccountName   string
	PDSTargetKUBECONFIG  string
	PDSUsername          string
	PDSPassword          string
	PDSIssuerURL         string
	PDSClientID          string
	PDSClientSecret      string
	PDSTargetClusterType string
}

// MustHaveEnvVariables return emnvironment variables.
func MustHaveEnvVariables() Environment {
	return Environment{
		PDSControlPlaneURL:   mustGetEnvVariable(envControlPlaneURL),
		PDSTestAccountName:   mustGetEnvVariable(envPDSTestAccountName),
		PDSTargetKUBECONFIG:  mustGetEnvVariable(envTargetKubeconfig),
		PDSUsername:          mustGetEnvVariable(envUsername),
		PDSPassword:          mustGetEnvVariable(envPassword),
		PDSIssuerURL:         mustGetEnvVariable(envPDSISSUERURL),
		PDSClientID:          mustGetEnvVariable(envPDSClientID),
		PDSClientSecret:      mustGetEnvVariable(envPDSClientSecret),
		PDSTargetClusterType: mustGetEnvVariable(envClusterType),
	}
}

// mustGetEnvVariable return environment variable.
func mustGetEnvVariable(key string) string {
	value, isExist := os.LookupEnv(key)
	if !isExist {
		log.Panicf("Key: %v doesn't exist", key)
	}
	return value
}

// GetBearerToken fetches the token.
func GetBearerToken() (string, error) {
	username := os.Getenv(envUsername)
	password := os.Getenv(envPassword)
	clientID := os.Getenv(envPDSClientID)
	clientSecret := os.Getenv(envPDSClientSecret)
	issuerURL := os.Getenv(envPDSISSUERURL)
	url := fmt.Sprintf("%s/protocol/openid-connect/token", issuerURL)
	grantType := "password"

	postBody, err := json.Marshal(map[string]string{
		"grant_type":    grantType,
		"client_id":     clientID,
		"client_secret": clientSecret,
		"username":      username,
		"password":      password,
	})
	if err != nil {
		return "", err
	}
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(url, "application/json", requestBody)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var bearerToken = new(BearerToken)
	err = json.Unmarshal(body, &bearerToken)
	if err != nil {
		return "", err
	}
	return bearerToken.AccessToken, nil
}

// GetContext return context for api call.
func GetContext() (context.Context, error) {
	log.Info("Check for environmental variable.")
	envVars := MustHaveEnvVariables()
	endpointURL, err := url.Parse(envVars.PDSControlPlaneURL)
	if err != nil {
		log.Errorf("Unable to access the URL: %s", envVars.PDSControlPlaneURL)
		return nil, err
	}
	apiConf := pds.NewConfiguration()
	apiConf.Host = endpointURL.Host
	apiConf.Scheme = endpointURL.Scheme
	token, err := GetBearerToken()
	if err != nil {
		return nil, err
	}
	ctx := context.WithValue(context.Background(), pds.ContextAPIKeys, map[string]pds.APIKey{"ApiKeyAuth": {Key: token, Prefix: "Bearer"}})
	return ctx, nil
}
