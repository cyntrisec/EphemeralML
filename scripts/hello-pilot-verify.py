#!/usr/bin/env python3
"""
EphemeralML Hello Pilot — OpenAI SDK Demo & Evidence Saver

Calls the EphemeralML gateway using the official OpenAI Python SDK
(with_raw_response for header access), extracts attestation receipt
headers, and saves evidence to pilot/evidence/.

Prerequisites:
    pip install openai

Usage:
    python3 scripts/hello-pilot-verify.py

    # Custom gateway URL:
    EPHEMERALML_GATEWAY_URL=http://10.0.0.1:8090 python3 scripts/hello-pilot-verify.py
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

GATEWAY_URL = os.environ.get("EPHEMERALML_GATEWAY_URL", "http://localhost:8090")
API_KEY = os.environ.get("EPHEMERALML_API_KEY", "not-needed")

# Evidence output directory (relative to repo root)
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
EVIDENCE_DIR = PROJECT_DIR / "pilot" / "evidence"


def main():
    try:
        from openai import OpenAI
    except ImportError:
        print("ERROR: 'openai' package not installed. Run: pip install openai")
        sys.exit(1)

    print(f"Gateway: {GATEWAY_URL}")
    print(f"Auth:    {'configured' if API_KEY != 'not-needed' else 'none'}")
    print()

    # --- Step 1: Call embeddings via OpenAI SDK ---
    print("Calling /v1/embeddings via OpenAI SDK...")

    test_input = "Patient presents with acute respiratory distress and bilateral infiltrates."

    client = OpenAI(base_url=f"{GATEWAY_URL}/v1", api_key=API_KEY)

    # Use with_raw_response to get both the parsed result and HTTP headers.
    raw = client.embeddings.with_raw_response.create(
        model="text-embedding-3-small",
        input=test_input,
        encoding_format="float",
    )

    if raw.status_code != 200:
        print(f"ERROR: Expected 200, got {raw.status_code}")
        print(raw.text[:500])
        sys.exit(1)

    parsed = raw.parse()
    resp_headers = dict(raw.headers)

    # --- Step 2: Extract receipt info ---
    print(f"  HTTP {raw.status_code}")

    embedding = parsed.data[0].embedding if parsed.data else []
    print(f"  Embedding dimension: {len(embedding)}")

    receipt_present = resp_headers.get("x-ephemeralml-receipt-present", "false")
    attestation_mode = resp_headers.get("x-ephemeralml-attestation-mode", "unknown")
    receipt_sha256 = resp_headers.get("x-ephemeralml-receipt-sha256", None)
    request_id = resp_headers.get("x-request-id", None)

    print(f"  Receipt present:     {receipt_present}")
    print(f"  Attestation mode:    {attestation_mode}")
    if receipt_sha256:
        print(f"  Receipt SHA-256:     {receipt_sha256[:32]}...")
    if request_id:
        print(f"  Request ID:          {request_id}")

    # Check for in-body metadata (raw JSON — SDK model won't include extra fields)
    body = json.loads(raw.text)
    metadata = body.get("_ephemeralml", None)
    if metadata:
        print(f"  Executed model:      {metadata.get('executed_model', '?')}")
        print(f"  Receipt ID:          {metadata.get('receipt_id', '?')}")

    print()

    # --- Step 3: Save evidence ---
    EVIDENCE_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_file = EVIDENCE_DIR / f"pilot-evidence-{timestamp}.json"

    evidence = {
        "timestamp": timestamp,
        "gateway_url": GATEWAY_URL,
        "endpoint": "/v1/embeddings",
        "input_text": test_input,
        "http_status": raw.status_code,
        "response_headers": {
            k: v
            for k, v in resp_headers.items()
            if k.startswith("x-ephemeralml") or k == "x-request-id"
        },
        "embedding_dimension": len(embedding),
        "embedding_first_5": embedding[:5] if len(embedding) >= 5 else embedding,
        "metadata": metadata,
    }

    with open(evidence_file, "w") as f:
        json.dump(evidence, f, indent=2)

    print(f"Evidence saved: {evidence_file.relative_to(PROJECT_DIR)}")
    print()

    # --- Step 4: Quick verification summary ---
    print("Verification summary:")

    # Core checks (must pass)
    core_checks = [
        ("HTTP 200 response", raw.status_code == 200),
        ("Non-empty embedding", len(embedding) > 0),
        ("Request ID present", request_id is not None),
    ]

    # Optional checks (informational — may not pass in mock mode)
    optional_checks = [
        ("Receipt header present", receipt_present == "true"),
        ("Attestation mode set", attestation_mode != "unknown"),
    ]

    core_pass = True
    for label, passed in core_checks:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}]  {label}")
        if not passed:
            core_pass = False

    for label, passed in optional_checks:
        status = "PASS" if passed else "INFO"
        note = "" if passed else " (expected in mock mode)"
        print(f"  [{status}]  {label}{note}")

    print()
    if core_pass:
        print("All core checks passed.")
    else:
        print("Some core checks failed.")

    return 0 if core_pass else 1


if __name__ == "__main__":
    sys.exit(main())
