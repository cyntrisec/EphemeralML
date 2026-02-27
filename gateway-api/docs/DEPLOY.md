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
| `EPHEMERALML_MODEL_CAPABILITIES` | No | `chat` | `chat`, `embeddings`, or `chat,embeddings` |
| `EPHEMERALML_EMBEDDING_BACKEND_ADDR` | No | — | Dedicated embedding backend IP:port |
| `EPHEMERALML_EMBEDDING_MODEL` | No | — | Model ID for embedding backend |
| `EPHEMERALML_RECONNECT_ENABLED` | No | `true` | Background reconnect with exponential backoff |
| `EPHEMERALML_RECONNECT_BACKOFF_BASE_MS` | No | `100` | Base delay (ms) for backoff |
| `EPHEMERALML_RECONNECT_BACKOFF_CAP_MS` | No | `30000` | Maximum delay (ms) cap |
| `EPHEMERALML_RECONNECT_HEALTH_INTERVAL_SECS` | No | `5` | Seconds between TCP liveness probes |

## Health Checks

The gateway exposes two health endpoints. See [`HEALTH.md`](HEALTH.md) for the
full contract (state machine, JSON schemas, operator action table).

```bash
# Liveness — always returns 200 (process alive)
curl http://gateway:8090/health
# Returns: {"status": "ok", "backend_connected": true, "version": "...", ...}

# Readiness — 200 when all backends connected, 503 otherwise
curl -sf http://gateway:8090/readyz
# Returns: {"ready": true, "backend_connected": true}
```

**Status values** in `/health`:

| Status | Condition | `reconnect_enabled` |
|--------|-----------|---------------------|
| `ok` | All configured backends connected | any |
| `reconnecting` | At least one backend disconnected | `true` |
| `degraded` | Some backends disconnected | `false` |
| `unavailable` | All backends disconnected (dual-backend only) | `false` |

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8090
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /readyz
    port: 8090
  initialDelaySeconds: 2
  periodSeconds: 5
```

### ECS Health Check

```json
{
  "healthCheck": {
    "command": ["CMD-SHELL", "curl -sf http://localhost:8090/readyz || exit 1"],
    "interval": 10,
    "timeout": 5,
    "retries": 3,
    "startPeriod": 15
  }
}
```

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
| `"degraded"` in `/health` | Backend disconnected, reconnect disabled | Check backend, send inference request (lazy connect), or enable `EPHEMERALML_RECONNECT_ENABLED=true` |
| `"reconnecting"` in `/health` | Backend disconnected, auto-reconnecting | Wait; check logs for backoff progress. If >2 min, check backend health |
| `"unavailable"` in `/health` | All backends disconnected, reconnect disabled | Check all backend processes, enable reconnect or restart gateway |
| Proxy returns 431/502 on large responses | Full receipt header too large | Keep `EPHEMERALML_RECEIPT_HEADER_FULL=false` (default) |

## TLS

The gateway itself serves plain HTTP. For TLS:
- **Cloud Run**: Automatic TLS termination
- **K8s/ECS**: Use an ingress controller or ALB with TLS
- **Standalone**: Put nginx or Caddy in front

The backend channel (gateway ↔ enclave) is always encrypted via
SecureChannel (HPKE + ChaCha20-Poly1305), regardless of outer TLS.
