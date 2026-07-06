#!/usr/bin/env bash
# Build the enclave Docker image, convert to an EIF, and print PCR0/PCR8.
# Run on the Nitro-enabled EC2 (needs docker + nitro-cli). From repo root:
#   deploy/build-eif.sh
set -euo pipefail

IMAGE="${IMAGE:-rng-engine:latest}"
EIF_OUT="${EIF_OUT:-rng.eif}"
# Enclave runs rng-service as a shaded jar on a JRE.
DOCKERFILE="${DOCKERFILE:-deploy/Dockerfile.enclave.jre}"

echo ">> docker build $IMAGE ($DOCKERFILE)"
docker build -f "$DOCKERFILE" -t "$IMAGE" .

echo ">> nitro-cli build-enclave -> $EIF_OUT"
# For a SIGNED image add: --private-key <KMS-ARN> --signing-certificate cert.pem
# (PCR8 is all-zero until you sign.)
nitro-cli build-enclave \
  --docker-uri "$IMAGE" \
  --output-file "$EIF_OUT" \
  ${SIGNING_KEY:+--private-key "$SIGNING_KEY"} \
  ${SIGNING_CERT:+--signing-certificate "$SIGNING_CERT"} \
  | tee build-enclave.json

echo
echo ">> Measurements (pin PCR0 + PCR8 in the game client):"
jq -r '.Measurements | to_entries[] | "  \(.key) = \(.value)"' build-enclave.json
