# EphemeralML GCP OpenAI Gateway E2E

This flow starts a local OpenAI-compatible gateway against a real GCP
Confidential Space backend, then exercises it with the official OpenAI Python
SDK and saves evidence under `evidence/`.

## What it proves

- local gateway can front a real GCP backend
- `/v1/models`, `/v1/chat/completions`, or `/v1/embeddings` can be exercised
- request ID and attestation metadata are surfaced as headers
- receipt metadata and AIR payload are returned in `_ephemeralml`

## Scripts

- `scripts/gcp/openai_gateway_e2e.sh`
  - starts the gateway locally
  - points it at a deployed GCP backend
  - runs the Python client
  - writes evidence to a timestamped directory

- `scripts/gcp/openai_gateway_client.py`
  - probes `/health`, `/readyz`, `/v1/models`
  - auto-selects `embeddings` or `chat` mode from model capabilities
  - saves headers and API result summary

## Prerequisites

- `gcloud auth login`
- `gcloud auth application-default login`
- `gcloud auth configure-docker us-docker.pkg.dev`
- Python packages:
  ```bash
  pip install openai httpx
  ```
- `.env.gcp` present with at least:
  - `EPHEMERALML_GCP_PROJECT`
  - `GCP_WIP_AUDIENCE`

## Fast rerun

If the backend is already deployed:

```bash
bash scripts/gcp/openai_gateway_e2e.sh \
  --project "$EPHEMERALML_GCP_PROJECT" \
  --docker \
  --skip-build \
  --ip BACKEND_EXTERNAL_IP
```

If the backend VM was auto-stopped:

```bash
gcloud compute instances start ephemeralml-cvm \
  --zone us-central1-a \
  --project "$EPHEMERALML_GCP_PROJECT"

gcloud compute instances describe ephemeralml-cvm \
  --zone us-central1-a \
  --project "$EPHEMERALML_GCP_PROJECT" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)'
```

Then reuse that IP with `openai_gateway_e2e.sh`.

## GPU / chat-capable rerun

For a chat-capable backend, deploy a GGUF-backed model first, then run:

```bash
bash scripts/gcp/openai_gateway_e2e.sh \
  --project "$EPHEMERALML_GCP_PROJECT" \
  --docker \
  --skip-build \
  --ip BACKEND_EXTERNAL_IP \
  --default-model tinyllama-chat \
  --model-capabilities chat
```

The Python client uses `/v1/models` capability metadata to decide whether to run
`chat` or `embeddings`. If you want to force a mode manually:

```bash
EPHEMERALML_OPENAI_TEST_MODE=chat \
EPHEMERALML_E2E_OUTPUT_DIR=/tmp/openai-gateway-chat \
python3 scripts/gcp/openai_gateway_client.py \
  --gateway-url http://127.0.0.1:8090 \
  --api-key test-key
```

## Evidence files

Each run writes:

- `health.json`
- `readyz.json`
- `models.json`
- `api_headers.json`
- `api_result.json`
- `summary.json`
- `gateway.log`
- `client_stdout.txt`

## Known limits

- this is a real E2E validation path, not a production load test
- gateway parity is partial, not full OpenAI API parity
- streaming is not supported
- chat requires a backend model that actually advertises `chat`
- if the deployed manifest model ID is not `stage-0`, pass it via
  `--default-model` so gateway-side receipt validation matches the runtime
