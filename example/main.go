package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	// vaultconnector "gitlab.com/lightnet-thailand/poc/application-poc/app/vault"

	vaultConnector "github.com/devops-genuine/k8s-vault-connector-for-go"
	"os"
	"io/ioutil"
)

func functionRender(w http.ResponseWriter, r *http.Request) {

	message := r.URL.Path
	fmt.Println("Start get Health Check.")
	message = "{\"status\":\"success\",\"message\":\"OK\"}"

	w.Write([]byte(message))
}

type dataSecret struct {
	CaCert    string `json:"ca-crt"`
	Password  int `json:"password"`
	SecretKey string `json:"secret_key"`
}

var secretDataVault dataSecret

func main() {

	fmt.Println(os.Getenv("APP_NAME"))
	fmt.Println(os.Getenv("MY_POD_NAMESPACE"))
	fmt.Println(os.Getenv("VAULT_URL"))
	fmt.Println(os.Getenv("VAULT_PORT"))
	fmt.Println(os.Getenv("SATOKEN_FILE"))

	jsonData, err := vaultConnector.VaultConnector()
	// jsonData, err := vaultconnector.VaultConnector()
	if err != nil {
		fmt.Println("FAIL", err)
		panic("Status after get vault is not successfully.")
	}

	byteJSONData, _ := json.Marshal(jsonData)
	json.Unmarshal(byteJSONData, &secretDataVault)

	fmt.Println("TEST GET VAULT0", string(byteJSONData))
	d1 := []byte(secretDataVault.CaCert)
	ioutil.WriteFile("./ca-cert.crt", d1, 0644)

	password := secretDataVault.Password
	fmt.Println("password", password)

	http.HandleFunc("/health", functionRender)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}

}