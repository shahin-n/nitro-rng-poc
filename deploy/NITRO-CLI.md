# nitro-cli cheatsheet

## Build / measure
```bash
# build EIF from a docker image -> prints PCR0/1/2 (PCR8 too if signed)
nitro-cli build-enclave --docker-uri rng-engine:latest --output-file rng.eif

# signed build (real PCR8 = signer identity)
nitro-cli build-enclave --docker-uri img --output-file rng.eif \
  --private-key arn:aws:kms:REGION:ACCT:key/ID --signing-certificate cert.pem

# re-read measurements of an existing EIF (no rebuild)
nitro-cli describe-eif --eif-path rng.eif
nitro-cli describe-eif --eif-path rng.eif | jq '.Measurements'
```

## Run
```bash
nitro-cli run-enclave --eif-path rng.eif --cpu-count 2 --memory 3500 --enclave-cid 16

# debug (console + ALL-ZERO PCRs — game rejects all-zero PCR0 by design)
nitro-cli run-enclave --eif-path rng.eif --cpu-count 2 --memory 3500 \
  --enclave-cid 16 --debug-mode --attach-console
```

## Observe
```bash
nitro-cli describe-enclaves                          # all enclaves: state + PCRs
nitro-cli describe-enclaves | jq -r '.[].EnclaveID'  # just IDs
nitro-cli describe-enclaves | jq -r '.[] | "cid=\(.EnclaveCID) \(.State) \(.NumberOfCPUs)cpu \(.MemoryMiB)MiB"'
```

## Console (debug-mode enclaves only)
```bash
EID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli console --enclave-id "$EID"             # stream stdout (Ctrl-C detaches)
timeout 20 nitro-cli console --enclave-id "$EID"  # snapshot
```

## Terminate
```bash
nitro-cli terminate-enclave --enclave-id "$EID"
nitro-cli terminate-enclave --all
```

## Allocator (host resource pool)
```bash
cat /etc/nitro_enclaves/allocator.yaml            # memory_mib / cpu_count
sudo systemctl restart nitro-enclaves-allocator   # apply changes
systemctl is-active nitro-enclaves-allocator
```

## Gotchas (this box)
- `--debug-mode` => PCR0 all-zero => attestation rejected by design. Non-debug for real runs.
- `console` only works on `--debug-mode` enclaves; prod enclaves have none.
- `--memory` / `--cpu-count` must fit the allocator pool, else E19/E11.
- need group `ne` + perms on `/dev/nitro_enclaves` (else E19 opening device).
- source-installed nitro-cli: blobs live in `/root/aws-nitro-enclaves-cli/blobs/$(uname -m)/`,
  must be copied to `/usr/share/nitro_enclaves/blobs/` (else E19 on `cmdline`).

## Most-used daily
`describe-enclaves` · `terminate-enclave --all` · `run-enclave` · `console` (debug) · `describe-eif`
