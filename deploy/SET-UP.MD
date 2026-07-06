add how to install aws

`aws kms get-public-key \
--key-id alias/rng-proxy-kms \
--region ap-southeast-1 \
--query PublicKey \
--output text | base64 -d > public_key.der` for getting public key


openssl ecparam -name secp384r1 -genkey -out private.pem

openssl req -new -key private.pem -sha384 -nodes -subj "/CN=NitroEnclaveTest/C=US/ST=WA/L=Seattle/O=Test/OU=Test" -out csr.pem

openssl x509 -req -days 20  -in csr.pem -out certificate.pem -sha384 -signkey private.pem
