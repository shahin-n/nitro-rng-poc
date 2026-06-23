#!/usr/bin/env bash
# Run the enclave. Drop --debug-mode for production (debug => all-zero PCRs,
# which the game client rejects by design).
#   deploy/run-enclave.sh            # production
#   DEBUG=1 deploy/run-enclave.sh    # debug console
set -euo pipefail

EIF="${EIF:-rng.eif}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY="${MEMORY:-2048}"     # MiB; must fit the enclave allocator pool
ENCLAVE_CID="${ENCLAVE_CID:-16}"

echo ">> terminating any running enclaves"
nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

ARGS=(--eif-path "$EIF" --cpu-count "$CPU_COUNT" --memory "$MEMORY" --enclave-cid "$ENCLAVE_CID")
if [[ "${DEBUG:-0}" == "1" ]]; then
  ARGS+=(--debug-mode --attach-console)
fi

echo ">> nitro-cli run-enclave ${ARGS[*]}"
nitro-cli run-enclave "${ARGS[@]}"
nitro-cli describe-enclaves
