## Status: RESOLVED (2026-01-27)
The immediate reboot issue was caused by the lack of an explicit `ENTRYPOINT` in our Dockerfile. 

### Resolution details:
- **Root Cause:** `nitro-cli build-enclave` (or the underlying Nitro initramfs) is picky about how the command is defined in the Docker image. If only `CMD` is used, the enclave's internal `init` might fail to determine the execution path, leading to an immediate, silent reboot at ~0.17s.
- **Fix:** Explicitly define `ENTRYPOINT ["/init"]` (or the application binary) in the `Dockerfile`.
- **Validation:** Verified via `busybox-smoke` and `vsock-pingpong` runs. Logs confirmed the PID1 wrapper (`/init`) successfully starting and launching the app.

### Key artifacts:
- Commit `b49017e`: Set explicit `ENTRYPOINT` and parameterized mode via ENV.
- Log `dawn-sage` (2026-01-27): Confirmed successful boot and vsock server startup.

### Mathematical & Cryptographic Observations (for the Brain Trust):
The NSM (Nitro Security Module) integration is verified. During the `quick-willow` run, we successfully extracted hardware-rooted measurements:
- **PCR 0-2:** `0000...` (Expected for unsigned/debug EIF).
- **PCR 3 (Metadata):** `c326a1669e016cc3731099de9edebf13c59bea3bbba8c367fae5580d5c6682a675b23449572b136975cbdac4ecf8c9d0`
- **PCR 4 (Code/Image):** `ad592e54c599f885470841666f757e57fc7b29ab7294d82e3a52501579dc68cebc9ed5628a470a00083d2dbdcdce2efb`
- **Attestation Doc:** Successfully generated (4466 bytes), confirming the enclave can prove its identity to KMS.

This confirms that Layer 1 security (Identity + Attestation) is ready for real KMS integration.

---

# EphemeralML hello-enclave / vsock-pingpong — Handoff Packet

## Goal
Run a simple Nitro Enclave that exposes an AF_VSOCK server (port 5000) and responds `ping -> pong`.

## Environment
- AWS region: `us-east-1`
- Host AMI: Amazon Linux 2023 (`ami-0e3008cbd8722baf0`)
- Instance type used in tests: `m6i.xlarge`
- Nitro CLI: `1.4.4`

## What we observed
- The AWS *known-good* sample `public.ecr.aws/aws-nitro-enclaves/hello:latest` runs fine and prints:
  - `Hello from the enclave side!` continuously
  - Enclave remains `State: RUNNING`
  - This strongly suggests Nitro/host setup is fundamentally OK.

- Our enclave image built from `enclaves/vsock-pingpong` **reboots almost immediately** inside the enclave:
  - console shows `reboot: Restarting system` and `reboot: machine restart`
  - then `nitro-cli` often reports console read error `E45` (ENOTCONN)
  - `nitro-cli describe-enclaves` shows `[]` shortly after

- Host `dmesg` often contains:
  - `nitro_enclaves: No CPUs available in CPU pool`
  - `nitro_enclaves: Error in setup CPU pool [rc=-22]`
  - However this **does not prevent** AWS hello sample from running.

## Most relevant logs
All logs are under:
- `projects/EphemeralML/infra/hello-enclave/logs/`

Key runs:
- `diag7-20260126T233227Z/` — AWS hello sample run; prints and stays RUNNING.
- `diag6-20260126T232858Z/` — our enclave with alpine runtime; still reboots.
- `diag8-20260126T234408Z/` — our new `basic` mode test (no vsock); still reboots.
- `diag9-20260126T234517Z/` — console tail confirming reboot+E45.

## Code changes made to support debugging
Repo: `projects/EphemeralML/enclaves/vsock-pingpong`

- Dockerfile runtime changed from `scratch` to `alpine:3.19`.
- Added selectable runtime mode:
  - `--mode basic` (sleep forever)
  - `--mode vsock` (actual vsock server)
- Docker build arg selects mode:
  - `docker build --build-arg MODE=basic -t ephemeralml/vsock-pingpong-basic:latest .`
  - `docker build --build-arg MODE=vsock -t ephemeralml/vsock-pingpong:latest .`

Commits:
- `9d15bd3` (alpine runtime)
- `84533f7` (basic/vsock modes + Dockerfile arg)

## Repro commands (on host)
### Known-good control
```bash
docker pull public.ecr.aws/aws-nitro-enclaves/hello:latest
nitro-cli build-enclave --docker-uri public.ecr.aws/aws-nitro-enclaves/hello:latest --output-file hello.eif
nitro-cli run-enclave --eif-path hello.eif --cpu-count 2 --memory 1024 --enclave-cid 17 --attach-console
```

### Our basic mode (expected to stay alive, but currently reboots)
```bash
docker build --build-arg MODE=basic -t ephemeralml/vsock-pingpong-basic:latest .
nitro-cli build-enclave --docker-uri ephemeralml/vsock-pingpong-basic:latest --output-file basic.eif
nitro-cli run-enclave --eif-path basic.eif --cpu-count 2 --memory 1024 --enclave-cid 16 --attach-console
```

## Suspicions / hypotheses to investigate
1) Something about how `nitro-cli build-enclave` is packaging/setting init for our Docker image causes immediate reboot.
2) Our image may be missing something required by the enclave init environment (despite alpine userspace).
3) Compare the *Dockerfile + entrypoint conventions* used by AWS hello sample vs ours.
4) Try an ultra-minimal image that mimics AWS hello sample packaging style.
5) Inspect the EIF metadata / init command inside EIF if possible.

## Next experiments
- Build a Docker image that matches AWS hello structure (their Dockerfile) but runs our binary.
- Remove shell `CMD ["/bin/sh","-c", ...]` and use a direct `CMD ["/vsock-pingpong","--mode","basic"]`.
- Try `ENTRYPOINT` vs `CMD` variants.
- If possible, run `nitro-cli console --enclave-id ...` separately (without attach-console) right after start.

