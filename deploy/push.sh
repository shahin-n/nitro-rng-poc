#!/usr/bin/env bash
# Push source zip to the Nitro EC2 over EC2 Instance Connect, then (optionally)
# unzip + build the EIF remotely. Run from the mac.
#
#   deploy/push.sh           # scp only
#   deploy/push.sh build     # scp + remote unzip + build-eif
set -euo pipefail

KEY="${KEY:-$HOME/.ssh/server-keys/staging}"
INSTANCE_ID="${INSTANCE_ID:-i-09d9bb7339565e4d1}"
HOST="${HOST:-gbrng@10.91.95.11}"
PROFILE="${PROFILE:-nitro-poc}"
ZIP="${ZIP:-/Users/admin/projects/vingame/rng-nitro-based-service.zip}"
PROXY="aws ec2-instance-connect open-tunnel --instance-id $INSTANCE_ID --profile $PROFILE"

echo ">> scp $ZIP -> $HOST"
scp -i "$KEY" -o ProxyCommand="$PROXY" "$ZIP" "$HOST:~/"

if [[ "${1:-}" == "build" ]]; then
  echo ">> remote unzip + build"
  ssh -i "$KEY" -o ProxyCommand="$PROXY" "$HOST" \
    'cd ~ && unzip -o rng-nitro-based-service.zip >/dev/null && cd rng-nitro-based-service && deploy/build-eif.sh'
fi

echo ">> done"
