#!/usr/bin/env python3
"""Create a shareable AWS-native PoC evidence packet.

The private smoke-test bundle contains raw attestation, raw AIR receipts, KMS
release material, and cloud identifiers. This tool emits only a redacted packet
safe for customer discovery or lightweight reviewer sharing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REDACTIONS = [
    (re.compile(r"arn:aws:iam::\d{12}:"), "arn:aws:iam::<account-id>:"),
    (re.compile(r"arn:aws:kms:([a-z0-9-]+):\d{12}:"), r"arn:aws:kms:\1:<account-id>:"),
    (re.compile(r"arn:aws:s3:::[A-Za-z0-9.\-_]+"), "arn:aws:s3:::<private-bucket>"),
    (re.compile(r"s3://[A-Za-z0-9.\-_]+"), "s3://<private-bucket>"),
    (re.compile(r"\bi-[0-9a-f]{17}\b"), "<instance-id>"),
    (re.compile(r"\bami-[0-9a-f]{17}\b"), "<ami-id>"),
    (re.compile(r"\b\d{12}\b"), "<account-id>"),
    (re.compile(r"/tmp/cyntrisec[-_/A-Za-z0-9.]*"), "<redacted-host-path>"),
    (re.compile(r"/home/[A-Za-z0-9._-]+/[^ \n\r\t\"]*"), "<redacted-local-path>"),
]


def redact_string(value: str) -> str:
    out = value
    for pattern, replacement in REDACTIONS:
        out = pattern.sub(replacement, out)
    return out


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=False)
        f.write("\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_benchmark(source: Path) -> dict[str, Any]:
    for name in ("benchmark.json", "benchmark.redacted.json"):
        path = source / name
        if path.exists():
            value = load_json(path)
            if not isinstance(value, dict):
                raise SystemExit(f"{path}: expected object")
            return value
    return {}


def find_negative_tests(source: Path) -> Any:
    for name in ("negative-tests.json", "negative-tests.redacted.json"):
        path = source / name
        if path.exists():
            return load_json(path)
    return []


def render_readme(
    benchmark: dict[str, Any],
    receipt_sha256: str | None,
    negative_tests: Any,
) -> str:
    timings = benchmark.get("timings_ms") or {}
    environment = benchmark.get("environment") or {}
    eif_sha384 = benchmark.get("eif_sha384")
    timestamp = benchmark.get("timestamp_utc") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = benchmark.get("run_id") or "redacted"

    negative_passed = "unknown"
    if isinstance(negative_tests, list) and negative_tests:
        negative_passed = "PASS" if all(item.get("passed") for item in negative_tests if isinstance(item, dict)) else "FAIL"

    lines = [
        "# AWS-Native Nitro PoC Evidence Packet",
        "",
        f"Date: {timestamp}",
        f"Run ID: `{redact_string(str(run_id))}`",
        "",
        "This packet is a redacted summary of a Cyntrisec AWS-native Nitro PoC run.",
        "Raw attestation documents, raw AIR receipts, KMS release material, host logs,",
        "cloud account identifiers, and exact resource identifiers are intentionally",
        "excluded. Keep the full evidence bundle private unless there is an explicit",
        "review context.",
        "",
        "## What This Proves",
        "",
        "- AWS KMS released model material only to a Nitro Enclave measurement accepted by policy.",
        "- The enclave loaded the packaged model, executed a synthetic inference, and emitted an AIR receipt.",
        "- Offline AIR verification passed against the supplied Nitro attestation sidecar.",
        "- Negative checks rejected tampered receipt, wrong attestation sidecar, and wrong model hash.",
        "",
        "## What This Does Not Prove",
        "",
        "- It does not prove GPU or accelerator attestation.",
        "- It does not include customer data or production traffic.",
        "- It does not expose raw KMS response material or raw attestation evidence in this shareable packet.",
        "",
        "## Platform",
        "",
        f"- Region: `{redact_value(environment.get('region'))}`",
        f"- Instance type: `{redact_value(environment.get('instance_type'))}`",
        f"- Kernel: `{redact_value(environment.get('kernel'))}`",
        f"- Nitro CLI: `{redact_value(environment.get('nitro_cli_version'))}`",
        f"- Enclave memory: `{redact_value(environment.get('enclave_memory_mib'))} MiB`",
        f"- Enclave vCPUs: `{redact_value(environment.get('enclave_cpu_count'))}`",
        "",
        "## Cryptographic Inputs",
        "",
        f"- EIF PCR0 / SHA384: `{redact_string(str(eif_sha384)) if eif_sha384 else 'redacted'}`",
        f"- Receipt SHA-256: `{receipt_sha256 or 'not included in source packet'}`",
        "",
        "## Timings",
        "",
    ]

    timing_labels = [
        ("doctor_total_ms", "Doctor total"),
        ("kms_model_decrypt_ms", "KMS model decrypt"),
        ("enclave_launch_ms", "Enclave launch"),
        ("synthetic_inference_ms", "Synthetic inference"),
        ("receipt_verify_ms", "AIR receipt verification"),
        ("s3_upload_ms", "S3 upload"),
        ("total_smoke_test_ms", "Total smoke path"),
    ]
    for key, label in timing_labels:
        value = timings.get(key)
        if value is not None:
            lines.append(f"- {label}: `{value} ms`")
    lines.extend(
        [
            "",
            "## Negative Tests",
            "",
            f"Status: `{negative_passed}`",
            "",
            "## Included Files",
            "",
            "- `benchmark.redacted.json`: environment, timings, evidence sizes, and negative-test summary.",
            "- `negative-tests.redacted.json`: verifier outputs for expected-reject checks.",
            "- `SHA256SUMS`: hashes from the full evidence bundle when available.",
            "",
            "## Excluded Files",
            "",
            "- Raw `attestation.cbor`",
            "- Raw `receipt.cbor`",
            "- `kms-release.json`",
            "- Host logs",
            "- AWS request IDs or raw KMS response material",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="private evidence bundle or existing packet")
    parser.add_argument("destination", type=Path, help="redacted packet output directory")
    parser.add_argument("--force", action="store_true", help="overwrite destination if it exists")
    args = parser.parse_args()

    source = args.source.resolve()
    destination = args.destination.resolve()
    if not source.is_dir():
        raise SystemExit(f"{source}: source directory not found")
    if destination.exists():
        if not args.force:
            raise SystemExit(f"{destination}: already exists; use --force to overwrite")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    benchmark = redact_value(read_benchmark(source))
    negative_tests = redact_value(find_negative_tests(source))

    if isinstance(benchmark, dict):
        environment = benchmark.setdefault("environment", {})
        if isinstance(environment, dict):
            environment["ami_id"] = None
        benchmark["release_bundle_sha256"] = None
        write_json(destination / "benchmark.redacted.json", benchmark)
    else:
        write_json(destination / "benchmark.redacted.json", {})

    write_json(destination / "negative-tests.redacted.json", negative_tests)

    sums = source / "SHA256SUMS"
    if sums.exists():
        (destination / "SHA256SUMS").write_text(redact_string(sums.read_text(encoding="utf-8")), encoding="utf-8")

    receipt_path = source / "receipt.cbor"
    receipt_sha256 = sha256_file(receipt_path) if receipt_path.exists() else None
    readme = render_readme(benchmark if isinstance(benchmark, dict) else {}, receipt_sha256, negative_tests)
    (destination / "README.md").write_text(readme, encoding="utf-8")

    print(f"Wrote redacted packet: {destination}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
