#!/usr/bin/env python3
"""
Mint a self-signed X.509 cert whose public key is an AWS KMS asymmetric key,
with the certificate signature produced by KMS (kms:Sign). No pkcs11.

Output: cert.pem  (use as nitro-cli --signing-certificate; PCR8 = hash of it)

Usage:
  pip install boto3 asn1crypto
  python3 kms_selfsign_cert.py --key-id alias/rng-enclave-signer \
      --region ap-southeast-1 --out cert.pem
Creds via instance role / env. Needs kms:GetPublicKey + kms:Sign on the key.
"""
import argparse
import datetime
import os

import boto3
from asn1crypto import keys, pem, x509


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key-id", required=True, help="KMS key id, ARN, or alias/...")
    ap.add_argument("--region", required=True)
    ap.add_argument("--out", default="cert.pem")
    ap.add_argument("--days", type=int, default=3650)
    ap.add_argument("--cn", default="rng-enclave-signer")
    ap.add_argument("--org", default="vingame")
    args = ap.parse_args()

    kms = boto3.client("kms", region_name=args.region)

    # SubjectPublicKeyInfo straight from KMS (DER)
    spki = keys.PublicKeyInfo.load(kms.get_public_key(KeyId=args.key_id)["PublicKey"])

    name = x509.Name.build({"common_name": args.cn, "organization_name": args.org})
    now = datetime.datetime.now(datetime.timezone.utc)
    sig_algo = {"algorithm": "sha384_ecdsa"}

    tbs = x509.TbsCertificate({
        "version": "v3",
        "serial_number": int.from_bytes(os.urandom(8), "big") | 1,
        "signature": sig_algo,
        "issuer": name,
        "validity": {
            "not_before": x509.Time({"utc_time": now}),
            "not_after": x509.Time({"utc_time": now + datetime.timedelta(days=args.days)}),
        },
        "subject": name,
        "subject_public_key_info": spki,
        "extensions": [
            {"extn_id": "basic_constraints", "critical": True,
             "extn_value": {"ca": False}},
            {"extn_id": "key_usage", "critical": True,
             "extn_value": {"digital_signature"}},
        ],
    })

    # KMS signs the TBSCertificate DER; ECDSA_SHA_384 returns an ASN.1/DER sig,
    # which is exactly what X.509 wants.
    sig = kms.sign(
        KeyId=args.key_id,
        Message=tbs.dump(),
        MessageType="RAW",
        SigningAlgorithm="ECDSA_SHA_384",
    )["Signature"]

    cert = x509.Certificate({
        "tbs_certificate": tbs,
        "signature_algorithm": sig_algo,
        "signature_value": sig,
    })

    with open(args.out, "wb") as f:
        f.write(pem.armor("CERTIFICATE", cert.dump()))
    print("wrote", args.out)


if __name__ == "__main__":
    main()
