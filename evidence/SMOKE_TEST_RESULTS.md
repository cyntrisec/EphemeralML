# Phase A: GCP Confidential Space Smoke Test Results

**Date:** 2026-02-13
**Instance:** ephemeralml-cvm (c3-standard-4, TDX, us-central1-a)
**CS Image:** confidential-space-debug-251200
**Container Image:** us-docker.pkg.dev/project-d3c20737-eec2-453d-8e5/ephemeralml/enclave:latest
**Container Digest:** sha256:36a2dbadcc920ea2d04626e8875684dfec2dd9cac60eaeee94ce6b550d50433e
**Mode:** --synthetic (configfs-tsm not accessible inside CS containers)

## Results

| Check | Status | Detail |
|-------|--------|--------|
| Cloud Build | PASS | Image built + pushed to AR in 5m03s (E2_HIGHCPU_8) |
| CVM Boot | PASS | c3-standard-4 TDX, Confidential Space debug, RUNNING |
| Container Start | PASS | CS Launcher pulled and started container |
| Model Load | PASS | MiniLM-L6-v2 (86.7 MB) loaded in 238.5ms |
| CS Launcher Token | PARTIAL | JWT token received; `eat_nonce` parse issue (string vs array) |
| Trust Evidence | PASS | Bundle emitted with model hash, keys, platform |
| Port Reachable | PASS | TCP 9000 reachable from external |
| Inference E2E | NOT TESTED | Enclave exited on first malformed connection |

## Overall: PARTIAL PASS

The core infrastructure works: Cloud Build, Artifact Registry, Confidential Space CVM boot, container launch, model loading, and CS Launcher socket integration. Two issues blocked full E2E:

### Issue 1: configfs-tsm not available inside CS containers

`/sys/kernel/config/tsm/report` is not exposed to containers on Confidential Space. The TDX attestation interface is only available to the host VM OS, not inside Docker containers. On CS, attestation flows through the **Launcher socket** (which we successfully accessed to get a JWT token).

**Fix:** The TDX attestation bridge needs a CS-native mode that uses the Launcher JWT token as the attestation document (or wraps it in the transport handshake envelope), instead of raw configfs-tsm quotes.

### Issue 2: Server exits on first failed connection

The stage worker exited with `Transport(Session(Closed))` when a raw TCP health-check connected without completing the protocol handshake. The server should retry on connection errors, not exit.

**Fix:** Wrap the accept loop in `run_stage_tcp` with error handling that logs and retries on individual connection failures.

### Issue 3 (minor): CS Launcher `eat_nonce` format

The JWT `eat_nonce` claim is returned as a string, but our parser expects a JSON array. This is a minor deserialization issue.

**Fix:** Accept both `string` and `[string]` formats for `eat_nonce` in `cs_token_client.rs`.

## Trust Evidence Bundle (from boot logs)

```
Platform:           tdx
Model ID:           stage-0
Quote Hash:         6167e32973d28d2b55c546a3fb8c428a825106dff09858956366a8600add6a94
HPKE Public Key:    7b5e5b064bab0031e2d6ba945916d1cf
Receipt Sign Key:   fa7c80894a6ea7dc871b3c7dfe21511f
Model Hash:         53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db
```

## Evidence Files

| File | Content |
|------|---------|
| `boot_logs.txt` | Full container-runner journalctl output |
| `instance_metadata.yaml` | GCE instance description (machine type, CS image, network) |
| `verify_output.txt` | verify.sh output (port not reachable after container exited) |
| `SMOKE_TEST_RESULTS.md` | This file |

## Cost

- Cloud Build: 3 successful builds x ~$0.003/min x 5min = ~$0.05
- c3-standard-4: ~$0.21/hr x ~0.5hr = ~$0.10
- **Total: ~$0.15**

## Next Steps (Phase B)

1. Implement CS-native attestation mode (Launcher JWT in handshake)
2. Fix server accept loop to retry on individual connection failures
3. Fix `eat_nonce` deserialization to accept string or array
4. Re-test with full E2E inference + receipt verification
