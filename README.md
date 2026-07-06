# rng-nitro-based-service

RNG inside an **AWS Nitro Enclave**, zero-trust end-to-end. Implements the
architecture in [RNG in AWS Nitro Enclaves](https://sgame.atlassian.net/wiki/spaces/BL/pages/4186406956/).

Maven multi-module monorepo, Java 24, plain grpc-java + BouncyCastle.

## Topology

```
Game (VPC A) ──gRPC/TCP──► RNG Proxy (VPC B, EC2) ──vsock──► RNG Engine (Nitro Enclave)
 game-service              proxy-service                      rng-service
```

**Trust boundary.** The EC2 host, the proxy and the vsock are **untrusted**. They
only ever relay a public attestation document and **opaque ciphertext**. A
compromised proxy can delay traffic but can never read, forge, or replay it.

## Modules

| Module | Role | Trust | Key deps |
|---|---|---|---|
| `proto` | transport (`Attest`, opaque `Serve`) + app payload (`app.proto`, encrypted-only) | — | protobuf, grpc |
| `common-crypto` | HPKE (X25519/HKDF-SHA256/ChaCha20-Poly1305) + ECDSA-P384/SHA-384 | trusted ends | BouncyCastle |
| `attestation` | COSE_Sign1 verify, cert chain → pinned Nitro root, PCR0/PCR8 assert | game side | BC, CBOR |
| `rng-service` | **RNG Engine** — boot keys, NSM `/dev/nsm`, HPKE serve | enclave | crypto, junixsocket-vsock, FFM, CBOR |
| `proxy-service` | **RNG Proxy** — pure ciphertext relay (no crypto dep by design) | untrusted | grpc, junixsocket-vsock |
| `game-service` | **Game** — CLI: attest → verify → HPKE call | trusted | crypto, attestation, grpc |

## Flow (matches the spec)

**A · Boot** — enclave generates ephemeral keys in RAM (never persisted):
`enc` (X25519) + `sign` (ECDSA P-384).

**B · Connect / Attest** (plaintext, all public):
```
Game -> client_nonce (32 bytes)
Engine -> NSM: attest{ public_key=enc_pub, user_data=sign_pub, nonce=client_nonce }
NSM  -> COSE_Sign1{ PCR0..8, enc_pub, sign_pub, nonce, leaf+chain }
Game verifies IN ORDER: COSE sig (ES384) -> chain to PINNED AWS Nitro root + expiry
            -> PCR0==release & PCR8==signer (reject all-zero) -> nonce match
            -> only then trust enc_pub / sign_pub
```

**C · Serve** (HPKE both ways, sign-then-encrypt; proxy sees ciphertext only):
```
Game  -> HPKE(enc_pub, SealedRequest{ op, game_pub, req_nonce })
Engine: decrypt -> run RNG -> SIGN(sign_priv, result||req_nonce)
        -> HPKE(game_pub, SignedResult{ result, req_nonce, signature })
Game  : decrypt -> verify signature under sign_pub -> check req_nonce
```

Primitives: **HPKE base mode** DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305;
**ECDSA P-384 / SHA-384**. The RNG ops (`NextInt`, `NextBytes`, `CommitReveal`)
live in `app.proto` — confidential, never visible to the proxy. `CommitReveal` is
served over a stream: the enclave pushes the signed commit hash, holds the
connection `delay_seconds` (its own clock), then pushes the signed seed+value.

### Wire details

- `game ↔ proxy`: gRPC `Attest`, unary `Serve` (NextInt/NextBytes), and
  server-streaming `ServeStream` (commit-reveal: enclave pushes commit frame, holds,
  then pushes reveal frame).
- `proxy ↔ engine`: vsock, 1 tag byte (`A`/`S`/`C`) + length-delimited protobuf. The
  proxy forwards bytes; it has no crypto/attestation/RNG dependency at all.
- HPKE wire = `enc(32B X25519) || aead_ct` packed into `SealedMessage.ciphertext`.

## Build

Requires JDK 24.

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 24)
mvn clean install
```

## Run

The enclave hop (NSM + vsock) only works on a **Nitro-enabled EC2 instance**;
off-enclave the crypto compiles and the HPKE/ECDSA layer is unit-verifiable, but
`Attest` fails (no `/dev/nsm`).

```bash
# 1. build & sign the enclave image (on a build host with docker + nitro-cli)
nitro-cli build-enclave --docker-uri rng-service:latest --output-file rng.eif \
  --private-key arn:aws:kms:REGION:ACCT:key/KEY_ID --signing-certificate cert.pem
# capture PCR0 + PCR8 from the output -> release manifest

# 2. run enclave (parent EC2)
nitro-cli run-enclave --eif-path rng.eif --cpu-count 4 --memory 8192

# 3. proxy on the parent host
PROXY_GRPC_PORT=50051 ENCLAVE_CID=16 RNG_VSOCK_PORT=5005 mvn -pl proxy-service exec:java

# 4. game CLI (pins from the release manifest)
PROXY_HOST=<proxy> PROXY_PORT=50051 \
PCR0=<96-hex> PCR8=<96-hex> \
mvn -pl game-service exec:java
```

`game-service` is a menu CLI (NextInt / NextBytes / CommitReveal / re-attest). It
attests on first call, then every reply is HPKE-decrypted and signature+nonce
verified before display.

### Env vars

| Var | Service | Default |
|---|---|---|
| `RNG_VSOCK_PORT` | engine, proxy | `5005` |
| `ENCLAVE_CID` | proxy | `16` |
| `PROXY_GRPC_PORT` | proxy | `50051` |
| `PROXY_HOST` / `PROXY_PORT` | game | `localhost` / `50051` |
| `PCR0` / `PCR8` | game | (required, from release manifest) |

## Security notes / status

- **Pinned root**: `attestation/src/main/resources/nitro-root-g1.pem` is the real
  AWS Nitro Enclaves root G1 (sha256 `6eb96883…`). Rotate only via reviewed change.
- Verification follows the spec checklist: COSE sig before reading fields; chain +
  expiry; PCR0/PCR8 assert; reject all-zero PCRs (debug enclaves); one-time nonce
  with constant-time compare; req_nonce anti-replay; signature over result.
- **NSM ioctl** (`NsmClient`): real `/dev/nsm` `_IOWR(0x0A,0,nsm_message)` via the JDK
  FFM API (`java.lang.foreign`; needs `--enable-native-access=ALL-UNNAMED`). The ioctl
  constant + struct layout are validated on a live Nitro instance only — exercise there
  before relying on it.
- HPKE + ECDSA round-trip is locally verified (seal/open, sign/verify, tamper-reject).
- `CommitReveal` is an enclave-pushed stream (`ServeStream`): the enclave sends the
  signed commit hash, holds the connection `delay_seconds` on its own clock, then pushes
  the signed seed+value. No session state; client verifies `SHA256(seed)==hash` and
  re-derives value.
- Maven: corp Artifactory (`artifactory.withmario.com`) 401s some classified
  artifacts; they fall back to Maven Central (`protoc-gen-grpc-java` was installed
  from central once).

## TODO before production

- Containerize `rng-service` + `nitro-cli build-enclave` in CI; lock `kms:Sign`,
  CloudTrail alarm; publish PCR0/PCR8 manifest; PCR0 revocation list.
- PrivateLink between VPC A (games) and the proxy.
- Connection pooling / async serve in the proxy; cache attested keys by `module_id`
  with leaf-cert-expiry-driven re-attest.
