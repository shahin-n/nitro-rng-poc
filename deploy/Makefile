# Deploy runbook for the signed-PCR-manifest release. Step-by-step targets.
#
# Order:
#   make sync            # push source + manifest-tool.jar to the rng host
#   make build-eif       # rebuild + KMS-sign the EIF  -> prints PCR0/PCR8
#   make verify-key      # box KMS key == pinned release-pub.pem  (must say MATCH)
#   make sign-manifest PCR0=<hex> PCR8=<hex>    # sign manifest.json + manifest.sig
#   make build-jars      # docker-build proxy/game jars, extract to ~/rng
#   make run-enclave     # terminate stale enclaves, run the new one (CID 16)
#   make proxy-config    # add manifest env to the systemd unit         (sudo)
#   make proxy-restart   # restart proxy, expect 'pcr-manifest=served'  (sudo)
#   make client          # copy game-service.jar to g-service:/tmp
#   make client-run      # run the interactive client (pick 4=re-attest)
#
#   make status          # enclaves + proxy port + manifest files
#   make proxy-kill      # kill a stale java squatting :8800 (if restart fails)

KEY     ?= ~/.ssh/server-keys/staging
PROFILE ?= nitro-poc
RUSER   ?= gbrng
# rng host: enclave + proxy
RNG     ?= i-09d9bb7339565e4d1
# client box
GSVC    ?= i-0593351153e9bdd6b

HOME_DIR ?= /home/gbrng
REPO     ?= $(HOME_DIR)/rng-nitro-based-service
RUNDIR   ?= $(HOME_DIR)/rng

ENCLAVE_CID ?= 16
CPU_COUNT   ?= 4
MEMORY      ?= 7168
PROXY_HOST  ?= 10.91.65.11
PROXY_PORT  ?= 8800
# g-service PATH java is 21; client jar needs 24. Use the shipped JDK.
CLIENT_JAVA ?= /home/gbrng/jdk/bin/java

MANIFEST_VERSION ?= 1
VALID_DAYS       ?= 30
PCR0 ?=
PCR8 ?=

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

TUN_RNG  = aws ec2-instance-connect open-tunnel --instance-id $(RNG) --profile $(PROFILE)
TUN_GSVC = aws ec2-instance-connect open-tunnel --instance-id $(GSVC) --profile $(PROFILE)
SSH_RNG  = ssh -i $(KEY) -o ProxyCommand="$(TUN_RNG)" $(RUSER)@$(RNG)
SSH_GSVC = ssh -i $(KEY) -o ProxyCommand="$(TUN_GSVC)" $(RUSER)@$(GSVC)
SCP_RNG  = scp -O -i $(KEY) -o ProxyCommand="$(TUN_RNG)"
SCP_GSVC = scp -O -i $(KEY) -o ProxyCommand="$(TUN_GSVC)"

.PHONY: help sync build-eif verify-key sign-manifest build-jars run-enclave \
        proxy-config proxy-restart proxy-kill client client-run status

help:
	@sed -n '3,16p' $(lastword $(MAKEFILE_LIST))

# 1 — sync changed source into the (non-git) box repo; ship the release tool
sync:
	$(SSH_RNG) 'mkdir -p $(REPO) $(RUNDIR)'
	cd $(ROOT) && tar czf - proto common-crypto common-random attestation rng-service proxy-service game-service manifest-tool pom.xml deploy \
	  | $(SSH_RNG) 'cd $(REPO) && tar xzf -'
	$(SCP_RNG) $(ROOT)/manifest-tool/target/manifest-tool.jar $(RUSER)@$(RNG):$(RUNDIR)/manifest-tool.jar
	@echo ">> synced source + manifest-tool.jar"

# 2 — rebuild + KMS-sign the EIF; copy PCR0/PCR8 from the output
build-eif:
	$(SSH_RNG) 'cd $(REPO) && . ~/kms/.env && CERT=$$(eval echo "$$CERT_PATH") && \
	  [ -f "$$CERT" ] || { echo ">> signing cert not found: $$CERT"; exit 1; } && \
	  SIGNING_KEY=$$KEY_ARN SIGNING_CERT=$$CERT deploy/build-eif.sh 2>&1 | tail -20'

# 3 — the manifest signer key (KMS) must equal the pinned release-pub.pem
verify-key:
	$(SSH_RNG) '. ~/kms/.env && R=$$(echo $$KEY_ARN|cut -d: -f4) && \
	  $(RUNDIR)/jdk/bin/java -jar $(RUNDIR)/manifest-tool.jar --key-id $$KEY_ARN --region $$R \
	    --export-pubkey /tmp/box-release-pub.pem'
	@$(SSH_RNG) 'cat /tmp/box-release-pub.pem' | diff - $(ROOT)/attestation/src/main/resources/release-pub.pem \
	  && echo ">> KEY MATCH — pinned release-pub.pem is correct" \
	  || { echo ">> KEY MISMATCH — STOP: re-pin release-pub.pem from this box, rebuild game jar"; exit 1; }

# 4 — sign the manifest for the new image (PCR0/PCR8 from step 2)
sign-manifest:
	@[ -n "$(PCR0)" ] && [ -n "$(PCR8)" ] || { echo "usage: make sign-manifest PCR0=<hex> PCR8=<hex>"; exit 1; }
	$(SSH_RNG) '. ~/kms/.env && R=$$(echo $$KEY_ARN|cut -d: -f4) && cd $(RUNDIR) && \
	  ./jdk/bin/java -jar manifest-tool.jar --key-id $$KEY_ARN --region $$R \
	    --service rng-service --version $(MANIFEST_VERSION) --valid-days $(VALID_DAYS) \
	    --pcr0 $(PCR0) --pcr8 $(PCR8) && ls -l manifest.json manifest.sig'

# 5 — build proxy + game jars in Docker, extract to ~/rng (host has no maven)
build-jars:
	$(SSH_RNG) 'cd $(REPO) && docker build -f deploy/Dockerfile.host -t rng-host:latest . && \
	  cid=$$(docker create rng-host:latest) && \
	  docker cp $$cid:/proxy-service.jar $(RUNDIR)/proxy-service.jar && \
	  docker cp $$cid:/game-service.jar $(RUNDIR)/game-service.jar && \
	  docker rm $$cid && echo ">> jars updated in $(RUNDIR)"'

# 6 — terminate stale enclaves, run the new signed one
run-enclave:
	$(SSH_RNG) 'cd $(REPO) && CPU_COUNT=$(CPU_COUNT) MEMORY=$(MEMORY) ENCLAVE_CID=$(ENCLAVE_CID) \
	  deploy/run-enclave.sh 2>&1 | tail'

# 7 — add manifest env to the proxy unit (sudo)
proxy-config:
	$(SSH_RNG) 'sudo mkdir -p /etc/systemd/system/rng-proxy.service.d && \
	  printf "[Service]\nEnvironment=PCR_MANIFEST_PATH=$(RUNDIR)/manifest.json\nEnvironment=PCR_MANIFEST_SIG_PATH=$(RUNDIR)/manifest.sig\n" \
	    | sudo tee /etc/systemd/system/rng-proxy.service.d/manifest.conf && \
	  sudo systemctl daemon-reload && echo ">> proxy manifest env set"'

# 8 — restart proxy; expect the log to show pcr-manifest=served (sudo)
proxy-restart:
	$(SSH_RNG) 'sudo systemctl restart rng-proxy && sleep 1 && \
	  systemctl is-active rng-proxy && \
	  (journalctl -u rng-proxy -n8 --no-pager | grep -iE "manifest|gRPC up" || journalctl -u rng-proxy -n8 --no-pager)'

# fallback — kill a stale manual java holding :8800
proxy-kill:
	$(SSH_RNG) 'pid=$$(sudo ss -ltnp | grep ":8800" | grep -o "pid=[0-9]*" | cut -d= -f2 | head -1); \
	  [ -n "$$pid" ] && sudo kill -9 $$pid && echo ">> killed $$pid" || echo ">> nothing on :8800"'

# 9 — ship the client jar to g-service:/tmp (hop via local)
client:
	$(SSH_RNG) 'cat $(RUNDIR)/game-service.jar' > /tmp/game-service.jar
	$(SCP_GSVC) /tmp/game-service.jar $(RUSER)@$(GSVC):/tmp/game-service.jar
	@echo ">> game-service.jar on g-service:/tmp (no PCR env needed — it fetches the signed manifest)"

# 10 — run the interactive client (menu 4 = re-attest first)
client-run:
	$(SSH_GSVC) -t 'PROXY_HOST=$(PROXY_HOST) PROXY_PORT=$(PROXY_PORT) \
	  $(CLIENT_JAVA) --enable-native-access=ALL-UNNAMED -jar /tmp/game-service.jar'

status:
	@$(SSH_RNG) 'nitro-cli describe-enclaves 2>/dev/null | jq -r ".[]|\"enclave \(.EnclaveID) CID=\(.EnclaveCID) \(.State)\"" || echo "no enclaves"; \
	  echo ---; sudo ss -ltnp 2>/dev/null | grep ":8800" || echo "no proxy on :8800"; \
	  echo ---; ls -l $(RUNDIR)/manifest.json $(RUNDIR)/manifest.sig 2>/dev/null || echo "no manifest files"'
