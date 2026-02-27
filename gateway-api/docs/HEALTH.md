# Health Contract

This document defines the health endpoint semantics for the EphemeralML gateway.
Operators should use this as the reference for configuring container orchestrator
probes, monitoring alerts, and runbook actions.

## Endpoints

| Endpoint | Purpose | HTTP status | Auth required |
|----------|---------|-------------|---------------|
| `GET /health` | **Liveness** — is the process alive? | Always `200` | No |
| `GET /readyz` | **Readiness** — can it serve traffic? | `200` when ready, `503` otherwise | No |

### Why `/health` always returns 200

`/health` is a **liveness probe**. It answers: "Is the gateway process running
and responsive?" Even when no backend is connected, the gateway process is
healthy — it can accept connections, serve `/v1/models`, and will connect to
the backend on the first inference request (or via background reconnect).

Returning a non-200 from a liveness probe would cause orchestrators (K8s, ECS)
to **kill and restart** the container, which is counterproductive when the
gateway is simply waiting for a backend that hasn't started yet.

### When to use `/readyz`

`/readyz` is a **readiness probe**. It answers: "Should traffic be routed to
this instance?" It returns `200` only when **all configured backends** are
connected. Use this for load balancer health checks and K8s readiness probes
so that traffic is not sent to a gateway that cannot serve inference requests.

## Status Values

The `status` field in `/health` responses takes one of four values:

| Status | Meaning |
|--------|---------|
| `ok` | All configured backends are connected. Inference requests will succeed. |
| `reconnecting` | One or more backends are disconnected and the background reconnect loop is active (`EPHEMERALML_RECONNECT_ENABLED=true`). The gateway is attempting to restore connectivity automatically. |
| `degraded` | One or more backends are disconnected and reconnect is **disabled** (`EPHEMERALML_RECONNECT_ENABLED=false`). Manual intervention or a new inference request (which triggers lazy connect) is needed. |
| `unavailable` | **All** backends are disconnected and reconnect is disabled. Only possible when a dedicated embedding backend is configured (`EPHEMERALML_EMBEDDING_BACKEND_ADDR`). In single-backend mode, the equivalent state is `degraded`. |

## State Machine

```
                          startup
                            │
                            ▼
                ┌───────────────────────┐
                │  reconnecting /       │
                │  degraded             │◄──────────────────────┐
                │  (no backends         │                       │
                │   connected)          │                       │
                └───────────┬───────────┘                       │
                            │                                   │
                  backend connects                    backend disconnects
                            │                          (probe fail or
                            ▼                           request error)
                ┌───────────────────────┐                       │
                │  ok                   │───────────────────────┘
                │  (all backends        │
                │   connected)          │
                └───────────────────────┘
```

### Dual-Backend Transitions (embedding backend configured)

When `EPHEMERALML_EMBEDDING_BACKEND_ADDR` is set, the gateway tracks two
backends independently. The status matrix:

| Chat backend | Embedding backend | `reconnect_enabled` | Status |
|--------------|-------------------|---------------------|--------|
| connected | connected | any | `ok` |
| connected | disconnected | `true` | `reconnecting` |
| connected | disconnected | `false` | `degraded` |
| disconnected | connected | `true` | `reconnecting` |
| disconnected | connected | `false` | `degraded` |
| disconnected | disconnected | `true` | `reconnecting` |
| disconnected | disconnected | `false` | `unavailable` |

### Single-Backend Transitions

| Backend | `reconnect_enabled` | Status |
|---------|---------------------|--------|
| connected | any | `ok` |
| disconnected | `true` | `reconnecting` |
| disconnected | `false` | `degraded` |

Note: `unavailable` is not possible in single-backend mode.

## JSON Response Schemas

### `/health`

```json
{
  "status": "ok | reconnecting | degraded | unavailable",
  "backend_connected": true,
  "version": "0.1.0",
  "reconnect_enabled": true,
  "embedding_backend_configured": true,
  "embedding_backend_connected": false
}
```

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `status` | string | Yes | One of: `ok`, `reconnecting`, `degraded`, `unavailable` |
| `backend_connected` | bool | Yes | Whether the main (chat) backend channel is established |
| `version` | string | Yes | Gateway crate version |
| `reconnect_enabled` | bool | Only when `true` | Present when background reconnect is active |
| `embedding_backend_configured` | bool | Only when embedding backend is set | `true` when `EPHEMERALML_EMBEDDING_BACKEND_ADDR` is configured |
| `embedding_backend_connected` | bool | Only when embedding backend is set | Whether the embedding backend channel is established |

### `/readyz`

```json
{
  "ready": true,
  "backend_connected": true,
  "embedding_backend_configured": true,
  "embedding_backend_connected": true
}
```

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `ready` | bool | Yes | `true` iff all configured backends are connected |
| `backend_connected` | bool | Yes | Main backend connection status |
| `embedding_backend_configured` | bool | Only when embedding backend is set | Whether a dedicated embedding backend is configured |
| `embedding_backend_connected` | bool | Only when embedding backend is set | Embedding backend connection status |

## Container Orchestrator Probe Mapping

### Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8090
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /readyz
    port: 8090
  initialDelaySeconds: 2
  periodSeconds: 5
  failureThreshold: 3
```

- **Liveness** (`/health`): Always 200 while the process is alive. If this
  fails, the process has crashed or is deadlocked — K8s should restart it.
- **Readiness** (`/readyz`): Returns 503 until all backends are connected.
  K8s will not route traffic to this pod until readiness passes.

### Amazon ECS

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

Use `/readyz` for the ECS health check so the task is only marked healthy
when the backend is connected. Set `startPeriod` to allow time for the
initial backend handshake.

### Docker Compose

```yaml
healthcheck:
  test: ["CMD", "curl", "-sf", "http://localhost:8090/readyz"]
  interval: 10s
  timeout: 5s
  retries: 3
  start_period: 15s
```

## Operator Action Table

| Status | What it means | Action |
|--------|---------------|--------|
| `ok` | All backends connected, inference operational | None — normal operation |
| `reconnecting` | Gateway is auto-reconnecting to a lost backend | **Wait.** Check gateway logs for backoff progress. If persists >2 min, check backend health and network. |
| `degraded` | Backend disconnected, no auto-reconnect | Check backend process. Restart backend or send an inference request (triggers lazy connect). Consider enabling `EPHEMERALML_RECONNECT_ENABLED=true`. |
| `unavailable` | All backends disconnected, no auto-reconnect | Check all backend processes. Verify network/firewall. Enable reconnect or restart the gateway after fixing backends. |

## Reconnect Configuration

These environment variables control the background reconnect loop. See
the [README configuration table](../README.md#configuration) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `EPHEMERALML_RECONNECT_ENABLED` | `true` | Enable/disable background reconnect loop |
| `EPHEMERALML_RECONNECT_BACKOFF_BASE_MS` | `100` | Base delay (ms) for exponential backoff |
| `EPHEMERALML_RECONNECT_BACKOFF_CAP_MS` | `30000` | Maximum delay (ms) for backoff cap |
| `EPHEMERALML_RECONNECT_HEALTH_INTERVAL_SECS` | `5` | Seconds between TCP liveness probes |

When `EPHEMERALML_RECONNECT_ENABLED=true` (default), a background task per
backend performs TCP liveness probes every `RECONNECT_HEALTH_INTERVAL_SECS`.
On disconnect, it reconnects with exponential backoff + full jitter (base
`RECONNECT_BACKOFF_BASE_MS`, capped at `RECONNECT_BACKOFF_CAP_MS`). Request
handlers also trigger instant reconnect via an internal `Notify`. All reconnect
attempts are bounded by a 5-second connect timeout.
