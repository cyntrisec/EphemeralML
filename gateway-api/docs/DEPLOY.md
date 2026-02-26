# Gateway Deployment Guide (GCP Confidential Space)

Minimal deployment of the EphemeralML OpenAI-compatible gateway on GCP
Confidential Space with Intel TDX. This is the strongest validated path.

## Prerequisites

- GCP project with Confidential Computing API enabled
- `c3-standard-4` or `a3-highgpu-1g` quota
- Model uploaded to GCS (encrypted or plaintext)
- Docker image pushed to Artifact Registry

## Architecture

```
Internet/VPC → [LB / Cloud Run] → EphemeralML Gateway (VM or container)
                                         │
                                         │ SecureChannel (HPKE + ChaCha20)
                                         ▼
                                   Confidential Space CVM
                                   (TDX, enclave binary)
```

## Step 1: Build and push images

```bash
# Gateway image
docker build -f gateway-api/Dockerfile -t us-docker.pkg.dev/$PROJECT/ephemeralml/gateway:latest .
docker push us-docker.pkg.dev/$PROJECT/ephemeralml/gateway:latest

# Enclave image (GCP mode)
docker build -f Dockerfile.gcp -t us-docker.pkg.dev/$PROJECT/ephemeralml/enclave:latest .
docker push us-docker.pkg.dev/$PROJECT/ephemeralml/enclave:latest
```

## Step 2: Deploy enclave on Confidential Space

```bash
gcloud compute instances create ephemeralml-enclave \
  --zone=us-central1-a \
  --machine-type=c3-standard-4 \
  --confidential-compute-type=TDX \
  --min-cpu-platform="Intel Sapphire Rapids" \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --maintenance-policy=TERMINATE \
  --metadata=startup-script='#!/bin/bash
    docker pull us-docker.pkg.dev/PROJECT/ephemeralml/enclave:latest
    docker run -p 9000:9000 us-docker.pkg.dev/PROJECT/ephemeralml/enclave:latest \
      --gcp --model-dir /app/model --model-id stage-0 --listen 0.0.0.0:9000'
```

## Step 3: Deploy gateway

The gateway can run on any VM or container platform (it doesn't need to be
confidential — it's a pass-through proxy). Place it in the same VPC as the
enclave.

```bash
docker run -d --name gateway -p 8090:8090 \
  -e EPHEMERALML_BACKEND_ADDR=10.128.0.XX:9000 \
  -e EPHEMERALML_DEFAULT_MODEL=stage-0 \
  -e EPHEMERALML_API_KEY=your-production-key \
  -e EPHEMERALML_INCLUDE_METADATA_JSON=true \
  us-docker.pkg.dev/$PROJECT/ephemeralml/gateway:latest
```

## Configuration Reference

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `EPHEMERALML_BACKEND_ADDR` | Yes | — | Internal IP:port of enclave |
| `EPHEMERALML_DEFAULT_MODEL` | No | `stage-0` | Must match enclave's `--model-id` |
| `EPHEMERALML_API_KEY` | **Recommended** | — | Bearer auth; use in production |
| `EPHEMERALML_GATEWAY_HOST` | No | `0.0.0.0` | Bind address |
| `EPHEMERALML_GATEWAY_PORT` | No | `8090` | Listen port |
| `EPHEMERALML_REQUEST_TIMEOUT_SECS` | No | `120` | Increase for large models |
| `EPHEMERALML_INCLUDE_METADATA_JSON` | No | `false` | Embed `_ephemeralml` in body |
| `EPHEMERALML_RECEIPT_HEADER_FULL` | No | `false` | Full receipt in header (proxy risk) |

## Health Checks

```bash
# Liveness probe
curl http://gateway:8090/health
# Returns: {"status": "ok", "backend_connected": true, ...}

# Readiness (backend must be connected)
curl -sf http://gateway:8090/health | jq -e '.backend_connected == true'
```

Use `/health` for container orchestrator probes (ECS, K8s, Cloud Run).
The gateway reports `"degraded"` when the backend channel is not yet established.

## Auth

When `EPHEMERALML_API_KEY` is set, all endpoints except `/health` require:

```
Authorization: Bearer <key>
```

The gateway uses constant-time comparison to prevent timing side-channels.

## CORS

CORS is permissive by default (all origins allowed). For production, place
the gateway behind a reverse proxy (nginx, Cloud Run, ALB) and configure
CORS there. The gateway itself does not restrict origins.

## Logging / PHI Safety

Default log level: `info`. Controlled via `RUST_LOG`:

```bash
RUST_LOG=ephemeralml_gateway=info   # default
RUST_LOG=ephemeralml_gateway=debug  # verbose
```

**PHI-safe by default:**
- Prompt bodies and generated text are **never** logged
- Logged: request IDs, model name, latency, receipt presence, error types
- Attestation headers contain cryptographic hashes, not PHI

## Common Failure Modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `502 Backend unavailable` | Enclave not running or unreachable | Check enclave health, VPC firewall |
| `504 Gateway Timeout` | Inference >120s | Increase `EPHEMERALML_REQUEST_TIMEOUT_SECS` |
| `401 Invalid API key` | Missing or wrong bearer token | Check `EPHEMERALML_API_KEY` |
| `"degraded"` in `/health` | Channel not yet established | First request triggers connection |
| Proxy returns 431/502 on large responses | Full receipt header too large | Keep `EPHEMERALML_RECEIPT_HEADER_FULL=false` (default) |

## TLS

The gateway itself serves plain HTTP. For TLS:
- **Cloud Run**: Automatic TLS termination
- **K8s/ECS**: Use an ingress controller or ALB with TLS
- **Standalone**: Put nginx or Caddy in front

The backend channel (gateway ↔ enclave) is always encrypted via
SecureChannel (HPKE + ChaCha20-Poly1305), regardless of outer TLS.
