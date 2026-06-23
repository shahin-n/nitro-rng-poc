# Deployment runbook (live Nitro EC2)

Topology recap:
```
game (anywhere) --gRPC/TCP:50051--> proxy (parent host) --vsock:5005--> rng-engine (enclave)
```
Enclave = GraalVM native binary of `rng-service`. Proxy + game = fat jars on the host.

---

## Step 1 — prerequisites (on the EC2)

```bash
nitro-cli --version
docker --version
systemctl is-active nitro-enclaves-allocator   # must be active
cat /etc/nitro_enclaves/allocator.yaml         # cpu/memory reserved for enclaves
nproc && free -m
jq --version || sudo yum install -y jq
```
The allocator must reserve enough vCPU/MiB for `--cpu-count` / `--memory` in step 4.
If inactive: `sudo systemctl enable --now nitro-enclaves-allocator`.

## Step 2 — get the code + build the enclave image -> EIF

```bash
git clone <repo> && cd rng-nitro-based-service
deploy/build-eif.sh         # docker build -> nitro-cli build-enclave -> prints PCRs
```
Production (signed, real PCR8):
```bash
SIGNING_KEY=arn:aws:kms:REGION:ACCT:key/KEY_ID SIGNING_CERT=cert.pem deploy/build-eif.sh
```
**Record PCR0 + PCR8** from the output — the game pins them.

## Step 3 — run the enclave

```bash
CPU_COUNT=2 MEMORY=2048 ENCLAVE_CID=16 deploy/run-enclave.sh
nitro-cli describe-enclaves      # confirm RUNNING, note EnclaveCID
```
Debug first boot (note: debug => all-zero PCRs, game will reject): `DEBUG=1 deploy/run-enclave.sh`

## Step 4 — proxy on the host

```bash
PROXY_GRPC_PORT=50051 ENCLAVE_CID=16 RNG_VSOCK_PORT=5005 \
  java -jar proxy-service/target/proxy-service.jar
```

## Step 5 — game client (attests with pinned PCRs)

```bash
PROXY_HOST=localhost PROXY_PORT=50051 \
PCR0=<from step 2> PCR8=<from step 2> \
  java -jar game-service/target/game-service.jar
```
Pick `4) re-attest` first — must print `attested OK`. Then run NextInt etc.; each
reply is HPKE-decrypted and signature+nonce verified before display.

---

## Source-install gotchas (hit on the staging box, Ubuntu 24.04 + nitro-cli built from source)

The AWS docs assume the packaged CLI. A from-source `nitro-cli` leaves these undone:

1. **Driver**: `sudo apt-get install -y linux-modules-extra-$(uname -r)` then `sudo modprobe nitro_enclaves` (aws kernel only).
2. **`ne` group missing**: `sudo groupadd -f ne && sudo usermod -aG ne $USER` (re-login).
3. **Device perms**: `/dev/nitro_enclaves` is `root:root` — `sudo chgrp ne /dev/nitro_enclaves && sudo chmod 660` + a udev rule `/etc/udev/rules.d/99-nitro-enclaves.rules`:
   `KERNEL=="nitro_enclaves", GROUP="ne", MODE="0660"`.
4. **Allocator service not installed**: copy `bootstrap/{nitro-enclaves-allocator,allocator.yaml,nitro-enclaves-allocator.service}` to `/usr/bin`, `/etc/nitro_enclaves`, `/etc/systemd/system`, then enable.
5. **Log/run dirs**: `sudo mkdir -p /var/log/nitro_enclaves /var/run/nitro_enclaves && sudo chown $USER:ne … && chmod 775` (else build-enclave fails **E19**).
6. **Blobs not installed**: `sudo cp -r /root/aws-nitro-enclaves-cli/blobs/$(uname -m)/. /usr/share/nitro_enclaves/blobs/` (else build-enclave **E19** on `cmdline`).

## Enclave image gotcha

The enclave init runs the Docker `ENTRYPOINT` with a **minimal PATH** via `execvpe` —
bare `java` fails (`execvpe: java: No such file or directory`, **E45**). Use the
absolute path: `/opt/java/openjdk/bin/java` (see `Dockerfile.enclave.jre`).

## Host proxy / game gotchas

- No JVM on the host: extract one from the image —
  `cid=$(docker create rng-host); docker cp $cid:/opt/java/openjdk/. ~/rng/jdk/; docker cp $cid:/proxy-service.jar ~/rng/; docker cp $cid:/game-service.jar ~/rng/`.
- **vsock from a container = EPERM** (Docker seccomp/apparmor blocks `AF_VSOCK`). Run the
  proxy directly on the host instead (host `/dev/vsock` is world-rw). It's a `systemd`
  unit `rng-proxy.service`.
- Background `java &` over ssh dies on disconnect — use the systemd unit.

## Notes / gotchas

- **Arch**: the EIF arch = the instance arch; the Docker build matches it automatically.
- **vsock CID**: parent is always CID 3; give the enclave a fixed CID (16 here) and
  pass the same to the proxy via `ENCLAVE_CID`.
- **native-image metadata**: generated at build time by the tracing agent
  (`NativeWarmup`). If the engine hits a missing-reflection error at runtime, add the
  class to `NativeWarmup` and rebuild, or drop a config under
  `rng-service/src/main/resources/META-INF/native-image/`.
- **PCR8 = 0…0** means the EIF is unsigned — fine for a first smoke test, but the
  game rejects all-zero PCR0 (debug enclaves) and you should pin a real signed PCR8
  for production.
