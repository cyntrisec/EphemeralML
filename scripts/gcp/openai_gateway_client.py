#!/usr/bin/env python3
"""
EphemeralML GCP OpenAI Gateway E2E Client

Calls a running EphemeralML gateway through the official OpenAI Python SDK,
auto-selects a supported capability from /v1/models, and saves evidence for
health, readiness, model metadata, response headers, and the API result.

Prerequisites:
    pip install openai httpx

Usage:
    python3 scripts/gcp/openai_gateway_client.py

    EPHEMERALML_GATEWAY_URL=http://127.0.0.1:8090 \
      EPHEMERALML_API_KEY=test-key \
      python3 scripts/gcp/openai_gateway_client.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exercise an EphemeralML gateway through the OpenAI SDK and save evidence."
    )
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("EPHEMERALML_GATEWAY_URL", "http://127.0.0.1:8090"),
        help="Gateway base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("EPHEMERALML_API_KEY", "not-needed"),
        help="Bearer token for gateway auth (default: %(default)s)",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "embeddings", "chat"],
        default=os.environ.get("EPHEMERALML_OPENAI_TEST_MODE", "auto"),
        help="Capability to exercise (default: auto)",
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("EPHEMERALML_E2E_OUTPUT_DIR", ""),
        help="Optional output directory for evidence",
    )
    parser.add_argument(
        "--embedding-input",
        default="Sensitive market commentary for embedding path validation.",
        help="Input text for embeddings mode",
    )
    parser.add_argument(
        "--chat-input",
        default="Summarize the main risk in one sentence.",
        help="Input text for chat mode",
    )
    return parser.parse_args()


def ensure_output_dir(path_hint: str) -> Path:
    if path_hint:
        out_dir = Path(path_hint)
    else:
        repo_root = Path(__file__).resolve().parents[2]
        out_dir = repo_root / "evidence" / f"openai-gateway-e2e-{utc_stamp()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def auth_headers(api_key: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    if api_key and api_key != "not-needed":
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    args = parse_args()
    out_dir = ensure_output_dir(args.output_dir)

    try:
        import httpx
    except ImportError:
        print("ERROR: missing dependency 'httpx'. Run: pip install httpx openai", file=sys.stderr)
        return 1

    try:
        from openai import OpenAI
    except ImportError:
        print("ERROR: missing dependency 'openai'. Run: pip install openai httpx", file=sys.stderr)
        return 1

    gateway_url = args.gateway_url.rstrip("/")
    headers = auth_headers(args.api_key)

    evidence: dict[str, Any] = {
        "timestamp": utc_stamp(),
        "gateway_url": gateway_url,
        "mode_requested": args.mode,
    }

    with httpx.Client(timeout=15.0) as http:
        health = http.get(f"{gateway_url}/health")
        readyz = http.get(f"{gateway_url}/readyz")
        models_resp = http.get(f"{gateway_url}/v1/models", headers=headers)

    if health.status_code != 200:
        print(f"ERROR: /health returned {health.status_code}", file=sys.stderr)
        return 1
    if readyz.status_code != 200:
        print(f"ERROR: /readyz returned {readyz.status_code}", file=sys.stderr)
        return 1
    if models_resp.status_code != 200:
        print(f"ERROR: /v1/models returned {models_resp.status_code}", file=sys.stderr)
        return 1

    health_json = health.json()
    readyz_json = readyz.json()
    models_json = models_resp.json()

    write_json(out_dir / "health.json", health_json)
    write_json(out_dir / "readyz.json", readyz_json)
    write_json(out_dir / "models.json", models_json)

    model_entry = (models_json.get("data") or [{}])[0]
    capabilities = (model_entry.get("_ephemeralml") or {}).get("capabilities") or {}
    chosen_mode = args.mode
    if chosen_mode == "auto":
        if capabilities.get("embeddings"):
            chosen_mode = "embeddings"
        elif capabilities.get("chat"):
            chosen_mode = "chat"
        else:
            print("ERROR: no supported capability found in /v1/models", file=sys.stderr)
            return 1

    client = OpenAI(base_url=f"{gateway_url}/v1", api_key=args.api_key)

    result_summary: dict[str, Any] = {
        "mode_used": chosen_mode,
        "capabilities": capabilities,
    }

    if chosen_mode == "embeddings":
        raw = client.embeddings.with_raw_response.create(
            model="text-embedding-3-small",
            input=args.embedding_input,
            encoding_format="float",
        )
        if raw.status_code != 200:
            print(f"ERROR: embeddings returned {raw.status_code}", file=sys.stderr)
            print(raw.text[:1000], file=sys.stderr)
            return 1
        parsed = raw.parse()
        body = json.loads(raw.text)
        result_summary.update(
            {
                "object": parsed.object,
                "vector_dim": len(parsed.data[0].embedding) if parsed.data else 0,
                "metadata": body.get("_ephemeralml"),
            }
        )
    else:
        raw = client.chat.completions.with_raw_response.create(
            model="gpt-4",
            messages=[{"role": "user", "content": args.chat_input}],
            max_tokens=64,
        )
        if raw.status_code != 200:
            print(f"ERROR: chat returned {raw.status_code}", file=sys.stderr)
            print(raw.text[:1000], file=sys.stderr)
            return 1
        parsed = raw.parse()
        body = json.loads(raw.text)
        result_summary.update(
            {
                "object": parsed.object,
                "response_model": parsed.model,
                "first_output": parsed.choices[0].message.content if parsed.choices else None,
                "metadata": body.get("_ephemeralml"),
            }
        )

    api_headers = {
        k: v
        for k, v in dict(raw.headers).items()
        if k.lower().startswith("x-ephemeralml") or k.lower() == "x-request-id"
    }
    write_json(out_dir / "api_headers.json", api_headers)
    write_json(out_dir / "api_result.json", result_summary)

    evidence.update(
        {
            "health": health_json,
            "readyz": readyz_json,
            "model_id": model_entry.get("id"),
            "capabilities": capabilities,
            "mode_used": chosen_mode,
            "api_headers": api_headers,
            "result_summary": result_summary,
        }
    )
    write_json(out_dir / "summary.json", evidence)

    request_id = api_headers.get("x-request-id")
    receipt_present = api_headers.get("x-ephemeralml-receipt-present", "false")
    attestation_mode = api_headers.get("x-ephemeralml-attestation-mode", "unknown")
    receipt_sha = api_headers.get("x-ephemeralml-receipt-sha256")

    print(f"Gateway:           {gateway_url}")
    print(f"Output dir:        {out_dir}")
    print(f"Mode used:         {chosen_mode}")
    print(f"Model ID:          {model_entry.get('id')}")
    print(f"Capabilities:      {capabilities}")
    print(f"Request ID:        {request_id or 'missing'}")
    print(f"Attestation mode:  {attestation_mode}")
    print(f"Receipt present:   {receipt_present}")
    if receipt_sha:
        print(f"Receipt SHA-256:   {receipt_sha[:32]}...")

    core_checks = [
        ("health 200", True),
        ("readyz 200", True),
        ("models returned", bool(models_json.get("data"))),
        ("request id present", bool(request_id)),
        ("attestation header present", attestation_mode != "unknown"),
    ]
    if chosen_mode == "embeddings":
        core_checks.append(("non-empty embedding", result_summary.get("vector_dim", 0) > 0))
    else:
        core_checks.append(("non-empty response", bool(result_summary.get("first_output"))))

    failures = [name for name, ok in core_checks if not ok]
    for name, ok in core_checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")

    if failures:
        print(f"\nFAILED checks: {', '.join(failures)}", file=sys.stderr)
        return 1

    print("\nAll core checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
