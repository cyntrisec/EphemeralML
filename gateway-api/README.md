# EphemeralML OpenAI-Compatible Gateway

Drop-in HTTP gateway that makes EphemeralML's confidential inference accessible
via the standard OpenAI API. Change `base_url` and get hardware-attested
inference with cryptographic receipts — no SDK changes required.

## Quick Start

### Local (with mock backend)

```bash
# Terminal 1: start the EphemeralML enclave (mock mode)
cargo run --release --features mock --bin ephemeral-ml-enclave -- \
    --model-dir test_assets/minilm --model-id stage-0

# Terminal 2: start the gateway
cargo run --release -p ephemeralml-gateway --features mock -- \
    --backend-addr 127.0.0.1:9000

# Terminal 3: call it
curl -s http://localhost:8090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello, world!"}],
    "max_tokens": 64
  }' | jq .
```

### Docker Compose (one command)

```bash
cd gateway-api
docker compose up --build

# In another terminal:
curl -s http://localhost:8090/health | jq .
curl -s http://localhost:8090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}],"max_tokens":32}' | jq .
```

### Docker (gateway only)

```bash
docker build -f gateway-api/Dockerfile -t ephemeralml-gateway .
docker run -p 8090:8090 \
  -e EPHEMERALML_BACKEND_ADDR=host.docker.internal:9000 \
  ephemeralml-gateway
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe + backend connection status |
| `GET` | `/v1/models` | List available models (OpenAI-compatible) |
| `POST` | `/v1/chat/completions` | Text generation (non-streaming) |
| `POST` | `/v1/responses` | Text generation (OpenAI Responses API, non-streaming) |
| `POST` | `/v1/embeddings` | Text embeddings |

## Attestation Metadata

### Response Headers (always present, proxy-safe)

| Header | Description |
|--------|-------------|
| `x-request-id` | Unique request identifier |
| `x-ephemeralml-attestation-mode` | Attestation platform (`mock`, `nitro-pcr`, `cs-tdx`) |
| `x-ephemeralml-receipt-present` | `true` or `false` — whether an AIR v1 receipt was produced |
| `x-ephemeralml-receipt-sha256` | SHA-256 of the receipt (when present) |
| `x-ephemeralml-model-manifest-sha256` | SHA-256 of the model manifest (when available) |

The full receipt is **not** sent in headers by default (proxy/LB header-size
limits are typically 4-8 KB, and receipts can exceed this). To opt in:

```bash
export EPHEMERALML_RECEIPT_HEADER_FULL=true  # adds x-ephemeralml-air-receipt-b64
```

### JSON Metadata (opt-in)

Set `EPHEMERALML_INCLUDE_METADATA_JSON=true` to add `_ephemeralml` to response bodies:

```json
{
  "id": "chatcmpl-...",
  "model": "stage-0",
  "choices": [...],
  "_ephemeralml": {
    "receipt_id": "abc-123",
    "attestation_mode": "cs-tdx",
    "executed_model": "stage-0",
    "requested_model": "gpt-4",
    "receipt_sha256": "a1b2c3...",
    "air_v1_receipt_b64": "0oRYJ...",
    "model_manifest_sha256": "d4e5f6..."
  }
}
```

### Model Semantics

The `model` field in the response always reflects the **actual backend model**
that executed the inference (i.e., `EPHEMERALML_DEFAULT_MODEL`), not the model
name sent by the caller. This prevents audit/compliance confusion.

When JSON metadata is enabled, both are visible:
- `_ephemeralml.executed_model` — what actually ran
- `_ephemeralml.requested_model` — what the caller asked for

## Configuration

All configuration is via environment variables (or CLI flags):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EPHEMERALML_BACKEND_ADDR` | Yes | — | Backend enclave address (`host:port`) |
| `EPHEMERALML_DEFAULT_MODEL` | No | `stage-0` | Backend model ID for inference calls |
| `EPHEMERALML_API_KEY` | No | — | Bearer token for gateway auth |
| `EPHEMERALML_GATEWAY_HOST` | No | `0.0.0.0` | Listen host |
| `EPHEMERALML_GATEWAY_PORT` | No | `8090` | Listen port |
| `EPHEMERALML_REQUEST_TIMEOUT_SECS` | No | `120` | Per-request backend timeout |
| `EPHEMERALML_INCLUDE_METADATA_JSON` | No | `false` | Include `_ephemeralml` in JSON body |
| `EPHEMERALML_RECEIPT_HEADER_FULL` | No | `false` | Full receipt in header (proxy risk) |

## Python Example (OpenAI SDK)

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8090/v1",
    api_key="your-key-here",  # or "not-needed" if no auth configured
)

# Chat completion
response = client.chat.completions.create(
    model="gpt-4",  # model name is passed through; backend uses EPHEMERALML_DEFAULT_MODEL
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Summarize this medical record."},
    ],
    max_tokens=256,
)
print(response.choices[0].message.content)
print(f"Executed model: {response.model}")  # shows actual backend model

# Check attestation metadata (raw HTTP response)
import httpx

resp = httpx.post(
    "http://localhost:8090/v1/chat/completions",
    headers={"Authorization": "Bearer your-key-here"},
    json={
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}],
    },
)
print("Receipt present:", resp.headers.get("x-ephemeralml-receipt-present"))
print("Receipt SHA-256:", resp.headers.get("x-ephemeralml-receipt-sha256", "n/a"))
print("Attestation:", resp.headers.get("x-ephemeralml-attestation-mode"))
```

```python
# Embeddings
embeddings = client.embeddings.create(
    model="text-embedding-3-small",
    input="Confidential patient data",
)
print(f"Dimensions: {len(embeddings.data[0].embedding)}")
```

```python
# Responses API (OpenAI /v1/responses)
import httpx

resp = httpx.post(
    "http://localhost:8090/v1/responses",
    headers={"Authorization": "Bearer your-key-here"},
    json={
        "model": "gpt-4",
        "input": "Summarize the key risks.",
        "max_output_tokens": 128,
    },
)
data = resp.json()
print(data["output"][0]["content"][0]["text"])
```

## SDK Smoke Tests

Run the automated smoke test against a running gateway:

```bash
pip install openai httpx
python scripts/smoke_test_openai.py

# With auth:
EPHEMERALML_API_KEY=your-key python scripts/smoke_test_openai.py

# Custom endpoint:
EPHEMERALML_GATEWAY_URL=http://10.0.0.1:8090 python scripts/smoke_test_openai.py
```

## Logging

The gateway uses structured logging with PHI-safe defaults:

- Request IDs, model names, latency, and receipt presence are logged
- **Prompt bodies and generated text are never logged**
- Control verbosity with `RUST_LOG`:

```bash
RUST_LOG=ephemeralml_gateway=debug cargo run -p ephemeralml-gateway ...
```

## Deployment

See [`docs/DEPLOY.md`](docs/DEPLOY.md) for a production deployment guide
(GCP Confidential Space with TDX).

## MVP Limitations

- **No streaming** (`stream=true` returns 400). Planned for a future release.
- **Single backend connection** — the gateway maintains one `SecureChannel` to the backend.
  Concurrent requests are serialized through a mutex. For production throughput,
  run multiple gateway instances behind a load balancer.
- **Token counts are approximate** (whitespace-split estimate, not real tokenizer).
- **No model routing** — all requests go to the configured `EPHEMERALML_DEFAULT_MODEL`.
  The response `model` field reflects the actual executed model.
- **`/v1/responses`** — minimal subset: no tools, no tool_choice, no streaming.
- **Reconnection** — if the backend channel breaks, the gateway marks itself
  disconnected and attempts to reconnect on the next request. There is no
  background reconnection loop.
- **PHI-safe logging** — prompts/outputs never logged; only request IDs, model, latency, receipt presence.

## Architecture

```
┌──────────────────┐     OpenAI API      ┌──────────────────────────┐
│  OpenAI SDK /    │ ──────────────────► │  EphemeralML Gateway     │
│  LangChain /     │  POST /v1/chat/     │  (Axum HTTP server)      │
│  curl / httpx    │  completions        │                          │
└──────────────────┘                     │  ┌────────────────────┐  │
                                         │  │ SecureEnclaveClient│  │
                                         │  │ (attested channel) │  │
                                         │  └────────┬───────────┘  │
                                         └───────────┼──────────────┘
                                                     │ SecureChannel
                                                     │ (HPKE + ChaCha20)
                                                     ▼
                                         ┌──────────────────────────┐
                                         │  EphemeralML Enclave     │
                                         │  (Nitro / TDX / H100 CC)│
                                         │  - Model inference       │
                                         │  - Receipt signing       │
                                         │  - Attestation           │
                                         └──────────────────────────┘
```
