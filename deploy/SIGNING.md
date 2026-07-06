# Signing the EIF (real PCR8)

Unsigned EIF => `PCR8 = 0…0`. Signed => `PCR8 = SHA384(0^48 || SHA384(cert_DER))`
— the **signer identity**, constant across releases (same cert), so games pin it once.
PCR0 changes per build; PCR8 only when the cert changes. Pin both.

**Only ECDSA keys are supported** for signing (secp384r1). Two ways:
- `nitro-cli build-enclave --private-key K --signing-certificate cert.pem` — sign at build.
- `nitro-cli sign-eif --eif-path e.eif --private-key K --signing-certificate cert.pem` — sign an existing EIF; `--private-key` can be a **local key file OR a KMS ARN**.

---

## A. Local ECDSA self-signed (AWS-documented; use this)

```bash
mkdir -p ~/keys && cd ~/keys
# 1. private key (ECDSA P-384)
openssl ecparam -name secp384r1 -genkey -out signer.key
chmod 600 signer.key
# 2. CSR
openssl req -new -key signer.key -sha384 -nodes \
  -subj "/CN=rng-enclave-signer/C=SG/O=vingame" -out csr.pem
# 3. self-signed cert (signed by its own key)
openssl x509 -req -days 365 -in csr.pem -out cert.pem -sha384 -signkey signer.key
```

Sign + deploy (`bootstrap.sh` runs the `sign-eif` step; `KEY_ARN` accepts a local key
file OR a KMS ARN):
```bash
cd ~/rng-nitro-based-service
KEY_ARN=~/keys/signer.key CERT_PATH=~/keys/cert.pem deploy/bootstrap.sh
```
Read measurements:
```bash
nitro-cli describe-eif --eif-path rng.eif | jq -r '.Measurements | {PCR0,PCR8}'
```

⚠️ `signer.key` is the secret that defines trust. `chmod 600`, keep it off the repo
(put it in `~/keys`, NOT the build context — it must not land in the docker image).
For prod, move signing to CI and lock the key down.

## B. KMS-resident key (key never leaves KMS)

`--private-key <KMS ARN>` makes nitro-cli call `kms:Sign`. The catch: the
`--signing-certificate` must carry **that KMS key's public key**. You can't plain
`openssl x509 -signkey` it (the private key isn't local). Options to mint that cert:

1. **ACM Private CA** (recommended): `kms:GetPublicKey` -> build CSR -> `acm-pca issue-certificate` -> `cert.pem`.
2. **KMS-signed self-cert** via the `aws-kms-pkcs11` OpenSSL provider (heavy build:
   needs aws-sdk-cpp; config `kms_key_id`+`aws_region`; `openssl req -engine pkcs11 -keyform engine`).

Then:
```bash
KEY_ARN=$(aws kms describe-key --key-id alias/rng-enclave-signer --query KeyMetadata.Arn --output text)
nitro-cli sign-eif --eif-path rng.eif --private-key "$KEY_ARN" --signing-certificate cert.pem
# or: KEY_ARN=$KEY_ARN CERT_PATH=cert.pem deploy/bootstrap.sh
# build role needs kms:Sign + kms:GetPublicKey on the key
```

## Cert validity gotcha
Expired cert => `run-enclave` fails E36/E39/E11. Renew the cert before it lapses.

## Pin in the game

Two ways a client learns the allowed measurements:

**A. Signed PCR manifest (production).** The client fetches `manifest.json` + `manifest.sig`
from the proxy (`GetPcrManifest`), verifies the signature under a pinned release public
key, then trusts the PCR set. The set holds MANY PCR0s at once, so several releases are
valid during a rotation → zero-downtime, many clients, no client change on rotation.

```bash
# build the release tool once:
mvn -q -pl manifest-tool -am package   # -> manifest-tool/target/manifest-tool.jar
JAR=manifest-tool/target/manifest-tool.jar

# pin the release trust anchor in the client (once): export the KMS public key
java -jar $JAR --key-id alias/rng-enclave-signer --region <r> \
    --export-pubkey attestation/src/main/resources/release-pub.pem   # commit this (public)

# sign a manifest (reuse the EIF-signing KMS key). During a v1->v2 roll, list BOTH PCR0s:
java -jar $JAR --key-id alias/rng-enclave-signer --region <r> \
    --service rng-service --version 43 --valid-days 30 \
    --pcr0 <PCR0_v1> --pcr0 <PCR0_v2> --pcr8 <PCR8>
# drop manifest.json + manifest.sig behind the proxy:
PCR_MANIFEST_PATH=manifest.json PCR_MANIFEST_SIG_PATH=manifest.sig <run proxy>

# client (no PCRs needed — it learns them from the signed manifest):
PROXY_HOST=localhost PROXY_PORT=50051 \
  ./jdk/bin/java --enable-native-access=ALL-UNNAMED -jar game-service.jar
```

Zero-downtime rotation: `manifest-tool` with `[v1,v2]` → deploy v2 enclaves (both
accepted) → drain v1 → re-sign with `[v2]` only, bump `--version`. `not_after` caps how
long a revoked PCR stays replayable; keep it short and re-sign on a schedule.

**No restarts needed:** the proxy file-watches `PCR_MANIFEST_PATH`/`_SIG_PATH` and
serves the new bytes on change; clients poll `GetPcrManifest` every
`MANIFEST_POLL_SECONDS` (default 30, `0` disables) and adopt a **higher** `--version`
(monotonic → old/replayed manifests ignored). So an update = just re-sign and drop the
two files in place. **Write atomically** (`mv` a temp file, or write `manifest.sig`
last) — a half-written json/sig pair is briefly signature-invalid and clients skip it
until the next consistent read.

**B. Env pins (dev only).** Skip the manifest, pin one measurement directly:
```bash
PCR0=<describe-eif> PCR8=<describe-eif> PROXY_HOST=localhost PROXY_PORT=50051 \
  ./jdk/bin/java --enable-native-access=ALL-UNNAMED -jar game-service.jar
```

## Hardening (arch checklist)
- Move signing to CI; lock `kms:Sign` to the CI principal; CloudTrail alarm.
- Reuse one signing cert across releases (stable PCR8); only PCR0 changes per build.
- Keep a PCR0 revocation list; pin PCR0 to block rollback → drop it from the manifest.
- Release manifest key = trust root; guard `kms:Sign` on it like the EIF signer.
- Bump `--version` monotonically; a client can cache the highest seen to reject rollback.
