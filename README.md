# crypto_sm
provide crypto functions with libsm.

```
service CryptoService {
    // Get crypto info
    rpc GetCryptoInfo(common.Empty) returns (GetCryptoInfoResponse);

    // Hash data
    rpc HashData(HashDataRequest) returns (common.HashResponse);

    // Verify hash of data
    rpc VerifyDataHash(VerifyDataHashRequest) returns (common.StatusCode);

    // Sign a message
    rpc SignMessage(SignMessageRequest) returns (SignMessageResponse);

    // Recover signature
    rpc RecoverSignature(RecoverSignatureRequest) returns (RecoverSignatureResponse);

    // check transactions
    rpc CheckTransactions(blockchain.RawTransactions) returns (common.StatusCode);
}
```

check https://github.com/cita-cloud/cita_cloud_proto/blob/WIP-v7.0.0/protos/crypto.proto to get more details 

```
USAGE:
    crypto run [OPTIONS]

OPTIONS:
    -c, --config <CONFIG_PATH>                   Chain config path [default: config.toml]
    -h, --help                                   Print help information
    -p, --private_key_path <PRIVATE_KEY_PATH>    private key path [default: private_key]
```

## build docker image
```
docker build -t citacloud/crypto_sm .
```
