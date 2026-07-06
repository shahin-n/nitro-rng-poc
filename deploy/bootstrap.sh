#!/usr/bin/env bash
# One-shot, idempotent deploy of the whole RNG Nitro stack on the parent EC2.
# Run ON the box from the repo root:  deploy/bootstrap.sh
#
# Does: system prereqs (driver, ne group, device perms, allocator, dirs, blobs)
#       -> build enclave EIF -> run enclave -> build host jars -> proxy service.
# Re-runnable: terminates/re-creates the enclave and restarts the proxy each time.
#
# Env overrides: ENCLAVE_CID(16) CPU_COUNT(4) MEMORY(7168) RNG_VSOCK_PORT(5005)
#                PROXY_GRPC_PORT(8800)
#                KEY_ARN  CERT_PATH(~/kms/cert.pem)  — KMS/local EIF signing (sign-eif);
#                unset => unsigned (PCR8 = zeros).
set -euo pipefail

SCRIPT="$(readlink -f "$0")"
REPO_DIR="$(cd "$(dirname "$SCRIPT")/.." && pwd)"
cd "$REPO_DIR"

ENCLAVE_CID=${ENCLAVE_CID:-16}
CPU_COUNT=${CPU_COUNT:-4}
MEMORY=${MEMORY:-7168}
VSOCK_PORT=${RNG_VSOCK_PORT:-5005}
GRPC_PORT=${PROXY_GRPC_PORT:-8800}
KEY_ARN=${KEY_ARN:-}
CERT_PATH=${CERT_PATH:-$HOME/kms/cert.pem}
NITRO_SRC=${NITRO_SRC:-/root/aws-nitro-enclaves-cli}
ARCH=$(uname -m)

system_prep() {
  echo "== [1/5] system prereqs =="
  if ! lsmod | grep -q nitro_enclaves; then
    sudo -n modprobe nitro_enclaves 2>/dev/null || {
      sudo -n apt-get update -y
      sudo -n apt-get install -y "linux-modules-extra-$(uname -r)"
      sudo -n modprobe nitro_enclaves
    }
  fi
  sudo -n groupadd -f ne
  sudo -n usermod -aG ne "$USER"
  sudo -n chgrp ne /dev/nitro_enclaves
  sudo -n chmod 660 /dev/nitro_enclaves
  echo 'KERNEL=="nitro_enclaves", GROUP="ne", MODE="0660"' \
    | sudo -n tee /etc/udev/rules.d/99-nitro-enclaves.rules >/dev/null
  sudo -n mkdir -p /var/log/nitro_enclaves /var/run/nitro_enclaves
  sudo -n chown "$USER":ne /var/log/nitro_enclaves /var/run/nitro_enclaves
  sudo -n chmod 775 /var/log/nitro_enclaves /var/run/nitro_enclaves
  sudo -n mkdir -p /usr/share/nitro_enclaves/blobs
  sudo -n cp -r "$NITRO_SRC/blobs/$ARCH/." /usr/share/nitro_enclaves/blobs/
  sudo -n chmod -R a+r /usr/share/nitro_enclaves/blobs
  if [ ! -x /usr/bin/nitro-enclaves-allocator ]; then
    sudo -n cp "$NITRO_SRC/bootstrap/nitro-enclaves-allocator" /usr/bin/
    sudo -n chmod +x /usr/bin/nitro-enclaves-allocator
  fi
  sudo -n mkdir -p /etc/nitro_enclaves
  printf -- '---\nmemory_mib: 8192\ncpu_count: 4\n' \
    | sudo -n tee /etc/nitro_enclaves/allocator.yaml >/dev/null
  sudo -n cp "$NITRO_SRC/bootstrap/nitro-enclaves-allocator.service" /etc/systemd/system/
  sudo -n systemctl daemon-reload
  sudo -n systemctl enable --now nitro-enclaves-allocator
}

build_enclave() {
  echo "== [2/5] build enclave image + EIF =="
  nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
  docker build -f deploy/Dockerfile.enclave.jre -t rng-engine:latest .
  nitro-cli build-enclave --docker-uri rng-engine:latest --output-file rng.eif > build-enclave.json
  if [ -n "$KEY_ARN" ]; then
    CERT_PATH=$(eval echo "$CERT_PATH")   # expand a leading ~ if passed literally
    [ -f "$CERT_PATH" ] || { echo "ERROR: signing cert not found: $CERT_PATH (set CERT_PATH to an absolute path)"; exit 1; }
    echo "== sign EIF (key=$KEY_ARN cert=$CERT_PATH) =="
    nitro-cli sign-eif --eif-path rng.eif --private-key "$KEY_ARN" --signing-certificate "$CERT_PATH"
    nitro-cli describe-eif --eif-path rng.eif > build-enclave.json   # re-read: signing rewrites PCR0 + sets PCR8
  fi
}

run_enclave() {
  echo "== [3/5] run enclave =="
  nitro-cli run-enclave --eif-path rng.eif --cpu-count "$CPU_COUNT" \
    --memory "$MEMORY" --enclave-cid "$ENCLAVE_CID" >/dev/null
  sleep 10
  echo "enclave state: $(nitro-cli describe-enclaves | jq -r '.[].State')"
}

host_artifacts() {
  echo "== [4/5] host image -> JRE + jars =="
  docker build -f deploy/Dockerfile.host -t rng-host:latest .
  rm -rf "$HOME/rng/jdk"; mkdir -p "$HOME/rng/jdk"
  cid=$(docker create rng-host:latest)
  docker cp "$cid:/opt/java/openjdk/." "$HOME/rng/jdk/"
  docker cp "$cid:/proxy-service.jar" "$HOME/rng/"
  docker cp "$cid:/game-service.jar" "$HOME/rng/"
  docker rm "$cid" >/dev/null
}

proxy_service() {
  echo "== [5/5] proxy systemd service =="
  sudo -n tee /etc/systemd/system/rng-proxy.service >/dev/null <<UNIT
[Unit]
Description=RNG Proxy (gRPC <-> enclave vsock)
After=network.target nitro-enclaves-allocator.service
[Service]
User=$USER
WorkingDirectory=$HOME/rng
Environment=ENCLAVE_CID=$ENCLAVE_CID RNG_VSOCK_PORT=$VSOCK_PORT PROXY_GRPC_PORT=$GRPC_PORT
ExecStart=$HOME/rng/jdk/bin/java -jar $HOME/rng/proxy-service.jar
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
  sudo -n systemctl daemon-reload
  sudo -n systemctl restart rng-proxy
  sudo -n systemctl enable rng-proxy >/dev/null 2>&1 || true
  sleep 4
  echo "proxy state: $(systemctl is-active rng-proxy)"
}

main() {
  if [ "${1:-}" != "run-only" ]; then
    system_prep
    # ne group not active in this shell yet -> re-exec once under it
    if ! id -nG | grep -qw ne; then
      echo ">> re-exec under 'ne' group"
      exec sg ne -c "$SCRIPT run-only"
    fi
  fi
  build_enclave
  run_enclave
  host_artifacts
  proxy_service

  PCR0=$(jq -r '.Measurements.PCR0' build-enclave.json)
  PCR8=$(jq -r '.Measurements.PCR8 // empty' build-enclave.json)
  [ -z "$PCR8" ] && PCR8=$(printf '0%.0s' $(seq 1 96))
  echo
  echo "============================================================"
  echo " DEPLOY COMPLETE"
  echo " PCR0=$PCR0"
  echo " PCR8=$PCR8"
  echo
  echo " Run the game CLI:"
  echo "   cd ~/rng && PCR0=$PCR0 PCR8=$PCR8 \\"
  echo "     PROXY_HOST=localhost PROXY_PORT=$GRPC_PORT \\"
  echo "     ./jdk/bin/java --enable-native-access=ALL-UNNAMED -jar game-service.jar"
  echo "============================================================"
}

main "$@"
