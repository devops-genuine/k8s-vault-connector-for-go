package vaultconnector

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// BodyReqAuthStruct to create struct for request body when authen vault engine
type BodyReqAuthStruct struct {
	JWT  string `json:"jwt"`
	Role string `json:"role"`
}

var bodyReqAuth BodyReqAuthStruct

// BodyResClientTokenStruct to create struct for body client_token
type BodyResClientTokenStruct struct {
	ClientToken string `json:"client_token"`
}

// BodyResAuthStruct to create struct for response body when login vault client
type BodyResAuthStruct struct {
	Auth BodyResClientTokenStruct `json:"auth"`
}

var bodyResAuth BodyResAuthStruct

// BodyResVaultDataStruct to create struct for body data
type BodyResVaultDataStruct struct {
	Data map[string]interface{} `json:"data"`
}

// BodyResVaultStruct to create struct for response body when get vault data
type BodyResVaultStruct struct {
	Data BodyResVaultDataStruct `json:"data"`
}

var bodyResVaultData BodyResVaultStruct

// VaultConnector for another application in golang can query secret data vault(version 2) in K8S cluster
func VaultConnector() (map[string]interface{}, error) {

	//appName := os.Getenv("APP_NAME")
	//namespace := os.Getenv("MY_POD_NAMESPACE")
	urlVault := os.Getenv("VAULT_URL") 		// https://vault-cluster-01.secrets, https://127.0.0.1
	portVault := os.Getenv("VAULT_PORT") 	// 8200
	secretMountpoint := os.Getenv("VAULT_SECRET_MOUNTPOINT")
	SERVICE_ACCOUNT_FILE := os.Getenv("SATOKEN_FILE")

	urlVault = urlVault + ":" + portVault
	// https://vault-cluster-01.secrets:8200
	// https://127.0.0.1:8200

	fmt.Println("--------------- Variable Application ---------------\nVault URL : " + urlVault+":"+portVault)
	fmt.Println("\nVault URL : " + urlVault)
	fmt.Println("\nSecret Mountpoint : " + secretMountpoint)

	// #################################################################################
	// #					          Get Service Account Token						   #
	// #################################################################################
	serviceAccountFile, err := os.Open(SERVICE_ACCOUNT_FILE)
	if err != nil {
		return nil, errors.Wrap(err, "vault connector fail, step get service account token")
	}

	defer serviceAccountFile.Close()
	serviceAccountToken, err := ioutil.ReadAll(serviceAccountFile)
	serviceAccountTokenString := strings.TrimSpace(string(serviceAccountToken))

	// #################################################################################
	// #					          Get Vault Access Token						   #
	// #################################################################################

	bodyReqAuth.JWT = serviceAccountTokenString
	//bodyReqAuth.Role = namespace + "-read-only-role"
    bodyReqAuth.Role = os.Getenv("VAULT_ROLE_NAME")

	jsonBodyReqAuth, _ := json.Marshal(bodyReqAuth)
	reqAuth, err := http.NewRequest("POST", urlVault+"/v1/auth/kubernetes/login", bytes.NewBuffer(jsonBodyReqAuth))
	reqAuth.Header.Set("Content-Type", "application/json")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resAuth, err := client.Do(reqAuth)
	if err != nil {
		return nil, errors.Wrap(err, "vault connector fail, step get service account token when calling login by vault api")
	}

	defer resAuth.Body.Close()
	bodyAccessToken, err := ioutil.ReadAll(resAuth.Body)
	if err != nil {
		return nil, errors.Wrap(err, "vault connector fail, step get vault access token when read response body")
	}

	json.Unmarshal(bodyAccessToken, &bodyResAuth)

	// #################################################################################
	// #					          Query Vault Data								   #
	// #################################################################################
	//reqVaultData, _ := http.NewRequest("GET", urlVault+"/v1/secret/data/"+namespace+"/apps/"+appName, nil)
	reqVaultData, _ := http.NewRequest("GET", urlVault+os.Getenv("VAULT_SECRET_MOUNTPOINT"), nil)
	reqVaultData.Header.Set("X-vault-Token", bodyResAuth.Auth.ClientToken)

	resQueryVault, err := client.Do(reqVaultData)
	if err != nil {
		return nil, errors.Wrap(err, "vault connector fail, step query vault data when calling vault api")
	}

	defer resQueryVault.Body.Close()
	resHTTPStatusCode := resQueryVault.StatusCode

	if resHTTPStatusCode == 204 {
		return nil, errors.Wrap(errors.New("no data return"), "vault connector fail, step query vault data. no data return(204)")
	} else if resHTTPStatusCode == 403 {
		return nil, errors.Wrap(errors.New("unauthorized"), "vault connector fail, step query vault data. unauthorized(403)")
	} else if resHTTPStatusCode == 404 {
		return nil, errors.Wrap(errors.New("secret not found"), "vault connector fail, step query vault data. secret not found(404)")
	} else if resHTTPStatusCode != 200 {
		return nil, errors.Wrap(errors.New("internal error"), "vault connector fail, step query vault data. internal error("+strconv.Itoa(resHTTPStatusCode)+")")
	}

	bodyVault, _ := ioutil.ReadAll(resQueryVault.Body)
	json.Unmarshal(bodyVault, &bodyResVaultData)

	return bodyResVaultData.Data.Data, nil
}
