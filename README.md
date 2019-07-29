# k8s-vault-connector-for-go

# Important! : This libray is upported only vault engine which it integerated with kubernetes api.

The library to connect and query secret data from vault engine for nodes, this library only supports for vault K/V secret version 2+.

## Run in local development
1) Port forward
```sh
NAMESPACE="secrets"
VAULTSERVICE="vault-cluster-01"
kubectl -n ${NAMESPACE} get vault ${VAULTSERVICE} -o jsonpath='{.status.vaultStatus.active}' | xargs -0 -I {} kubectl -n ${NAMESPACE} port-forward {} 8200
```

2) Export required environment variables
```sh
export VAULT_URL="https://localhost"
export VAULT_PORT="8200"
export VAULT_ROLE_NAME="develop-environment-readonly-role"
export VAULT_SECRET_MOUNTPOINT="/v1/secret/data/develop/apps/api-gateway-service"
export SATOKEN_FILE="/tmp/SAToken"  # Define only on localhost, after deployed to kubenetes, automatic use /var/run/secrets/kubernetes.io/serviceaccount/token
```
3) Install connector as dependency
```sh
go get github.com/devops-genuine/k8s-vault-connector-for-go@<RELEASE_VERSION>
go get github.com/devops-genuine/k8s-vault-connector-for-go@1.0.0
```
4) How to use, you can check it out in example folder
