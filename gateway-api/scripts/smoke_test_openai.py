#!/usr/bin/env python3
"""
Smoke test: verify EphemeralML gateway works with the official OpenAI Python SDK.

Prerequisites:
    pip install openai httpx

Usage:
    # Start the gateway (see README), then:
    python scripts/smoke_test_openai.py

    # With auth:
    EPHEMERALML_API_KEY=your-key python scripts/smoke_test_openai.py

    # Custom endpoint:
    EPHEMERALML_GATEWAY_URL=http://10.0.0.1:8090 python scripts/smoke_test_openai.py

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

import json
import os
import sys
import traceback

GATEWAY_URL = os.environ.get("EPHEMERALML_GATEWAY_URL", "http://localhost:8090")
API_KEY = os.environ.get("EPHEMERALML_API_KEY", "not-needed")

passed = 0
failed = 0


def check(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS  {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        traceback.print_exc()
        failed += 1


# ---------------------------------------------------------------------------
# 1. Health check (raw HTTP — no SDK needed)
# ---------------------------------------------------------------------------

def test_health():
    import httpx
    resp = httpx.get(f"{GATEWAY_URL}/health", timeout=5)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    data = resp.json()
    assert "status" in data, f"missing 'status' key: {data}"


# ---------------------------------------------------------------------------
# 2. Chat completions via OpenAI SDK
# ---------------------------------------------------------------------------

def test_chat_completions():
    from openai import OpenAI
    client = OpenAI(base_url=f"{GATEWAY_URL}/v1", api_key=API_KEY)
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Say hello."},
        ],
        max_tokens=32,
    )
    assert resp.id.startswith("chatcmpl-"), f"unexpected id: {resp.id}"
    assert resp.object == "chat.completion", f"unexpected object: {resp.object}"
    assert len(resp.choices) >= 1, "no choices returned"
    assert resp.choices[0].message.role == "assistant"
    # Model should reflect backend, not caller's "gpt-4"
    assert resp.model is not None, "model field missing"


# ---------------------------------------------------------------------------
# 3. Chat completions — attestation headers (raw HTTP)
# ---------------------------------------------------------------------------

def test_chat_headers():
    import httpx
    headers = {"Content-Type": "application/json"}
    if API_KEY and API_KEY != "not-needed":
        headers["Authorization"] = f"Bearer {API_KEY}"
    resp = httpx.post(
        f"{GATEWAY_URL}/v1/chat/completions",
        headers=headers,
        json={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16,
        },
        timeout=30,
    )
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    assert "x-request-id" in resp.headers, "missing x-request-id header"
    assert "x-ephemeralml-receipt-present" in resp.headers, "missing receipt-present header"
    assert "x-ephemeralml-attestation-mode" in resp.headers, "missing attestation-mode header"
    # Full receipt header should NOT be present by default
    assert "x-ephemeralml-air-receipt-b64" not in resp.headers, \
        "full receipt header should not be present by default (proxy safety)"


# ---------------------------------------------------------------------------
# 4. Embeddings via OpenAI SDK
# ---------------------------------------------------------------------------

def test_embeddings():
    from openai import OpenAI
    client = OpenAI(base_url=f"{GATEWAY_URL}/v1", api_key=API_KEY)
    resp = client.embeddings.create(
        model="text-embedding-3-small",
        input="Confidential patient data",
    )
    assert resp.object == "list"
    assert len(resp.data) >= 1
    assert len(resp.data[0].embedding) > 0, "empty embedding vector"


# ---------------------------------------------------------------------------
# 5. /v1/responses endpoint (raw HTTP — SDK may not have this yet)
# ---------------------------------------------------------------------------

def test_responses():
    import httpx
    headers = {"Content-Type": "application/json"}
    if API_KEY and API_KEY != "not-needed":
        headers["Authorization"] = f"Bearer {API_KEY}"
    resp = httpx.post(
        f"{GATEWAY_URL}/v1/responses",
        headers=headers,
        json={
            "model": "gpt-4",
            "input": "Say hello.",
            "max_output_tokens": 32,
        },
        timeout=30,
    )
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["object"] == "response", f"unexpected object: {data.get('object')}"
    assert data["status"] == "completed"
    assert len(data["output"]) >= 1
    assert data["output"][0]["content"][0]["type"] == "output_text"


# ---------------------------------------------------------------------------
# 6. Stream rejection
# ---------------------------------------------------------------------------

def test_stream_rejected():
    import httpx
    headers = {"Content-Type": "application/json"}
    if API_KEY and API_KEY != "not-needed":
        headers["Authorization"] = f"Bearer {API_KEY}"
    resp = httpx.post(
        f"{GATEWAY_URL}/v1/chat/completions",
        headers=headers,
        json={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        },
        timeout=10,
    )
    assert resp.status_code == 400, f"expected 400, got {resp.status_code}"
    data = resp.json()
    assert data["error"]["code"] == "unsupported_stream"


# ---------------------------------------------------------------------------
# 7. Models list
# ---------------------------------------------------------------------------

def test_models():
    from openai import OpenAI
    client = OpenAI(base_url=f"{GATEWAY_URL}/v1", api_key=API_KEY)
    models = client.models.list()
    assert len(models.data) >= 1, "no models returned"
    assert models.data[0].owned_by == "ephemeralml"


# ---------------------------------------------------------------------------
# Run all
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"EphemeralML Gateway Smoke Test — {GATEWAY_URL}")
    print(f"Auth: {'configured' if API_KEY != 'not-needed' else 'none'}")
    print()

    check("Health check", test_health)
    check("Models list", test_models)
    check("Chat completions (SDK)", test_chat_completions)
    check("Chat headers (attestation)", test_chat_headers)
    check("Embeddings (SDK)", test_embeddings)
    check("Responses endpoint", test_responses)
    check("Stream rejection", test_stream_rejected)

    print()
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)
