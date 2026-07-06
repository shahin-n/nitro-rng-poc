# release-pub.pem — the pinned release signing key

This directory should contain `release-pub.pem`: the **public** half of the AWS KMS
asymmetric ECDSA-P384 key that signs the PCR manifest (see `deploy/sign-manifest.py`).
It is the client's trust anchor for *which enclave images are allowed* — as load-bearing
as `nitro-root-g1.pem`.

It is a **public** key: safe to commit. Generate/refresh it with:

```bash
mvn -q -pl manifest-tool -am package
java -jar manifest-tool/target/manifest-tool.jar \
    --key-id alias/rng-enclave-signer --region <region> \
    --export-pubkey attestation/src/main/resources/release-pub.pem
```

If `release-pub.pem` is absent, `ReleaseKey.loadPinned()` fails closed. A client may
instead point `RELEASE_PUBKEY_PATH` at a PEM file, or use the dev env pins (`PCR0`/`PCR8`)
to bypass the manifest entirely.
