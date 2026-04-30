#!/usr/bin/env python3
"""Summarize AWS-native PoC benchmark JSON files.

The smoke-test runner emits benchmark.json in private evidence bundles. The
shareable packet uses benchmark.redacted.json. This tool accepts either shape.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any


METRICS = [
    ("doctor_total_ms", "Doctor total"),
    ("kms_model_decrypt_ms", "KMS model decrypt"),
    ("enclave_launch_ms", "Enclave launch"),
    ("synthetic_inference_ms", "Synthetic inference"),
    ("receipt_verify_ms", "AIR receipt verify"),
    ("s3_upload_ms", "S3 upload"),
    ("total_smoke_test_ms", "Total smoke path"),
    ("warm_path_without_enclave_launch_ms", "Warm path without enclave launch"),
    ("crypto_path_ms", "KMS decrypt + receipt verify"),
]


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return data


def discover(inputs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for item in inputs:
        if item.is_dir():
            files.extend(sorted(item.rglob("benchmark.json")))
            files.extend(sorted(item.rglob("benchmark.redacted.json")))
        elif item.is_file():
            files.append(item)
        else:
            raise SystemExit(f"{item}: not found")
    unique: dict[Path, None] = {}
    for path in files:
        unique[path.resolve()] = None
    return list(unique.keys())


def as_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def enrich_timings(timings: dict[str, Any]) -> dict[str, float]:
    values: dict[str, float] = {}
    for key, value in timings.items():
        number = as_number(value)
        if number is not None:
            values[key] = number

    total = values.get("total_smoke_test_ms")
    launch = values.get("enclave_launch_ms")
    if total is not None and launch is not None and total >= launch:
        values["warm_path_without_enclave_launch_ms"] = total - launch

    kms = values.get("kms_model_decrypt_ms")
    verify = values.get("receipt_verify_ms")
    if kms is not None and verify is not None:
        values["crypto_path_ms"] = kms + verify

    return values


def percentile(sorted_values: list[float], quantile: float) -> float:
    if not sorted_values:
        raise ValueError("empty values")
    rank = max(1, math.ceil(quantile * len(sorted_values)))
    return sorted_values[rank - 1]


def stat(values: list[float]) -> dict[str, float | int]:
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "min": ordered[0],
        "p50": statistics.median(ordered),
        "mean": statistics.fmean(ordered),
        "p95": percentile(ordered, 0.95),
        "max": ordered[-1],
    }


def fmt_ms(value: float | int) -> str:
    if isinstance(value, int):
        return str(value)
    if value.is_integer():
        return str(int(value))
    return f"{value:.1f}"


def collect(paths: list[Path]) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    metric_values: dict[str, list[float]] = {key: [] for key, _ in METRICS}
    env_values: dict[str, set[str]] = {}

    for path in paths:
        data = load_json(path)
        timings = enrich_timings(data.get("timings_ms") or {})
        environment = data.get("environment") or {}
        if not isinstance(environment, dict):
            environment = {}

        for key in metric_values:
            if key in timings:
                metric_values[key].append(timings[key])

        for key, value in environment.items():
            if value is not None:
                env_values.setdefault(key, set()).add(str(value))

        runs.append(
            {
                "path": str(path),
                "run_id": data.get("run_id"),
                "timestamp_utc": data.get("timestamp_utc"),
                "timings_ms": timings,
                "environment": environment,
            }
        )

    return {
        "run_count": len(runs),
        "runs": runs,
        "metrics": {
            key: stat(values)
            for key, values in metric_values.items()
            if values
        },
        "environment": {
            key: sorted(values)
            for key, values in sorted(env_values.items())
            if values
        },
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# AWS-Native PoC Benchmark Summary")
    lines.append("")
    lines.append(f"Runs: `{summary['run_count']}`")
    lines.append("")

    environment = summary.get("environment") or {}
    if environment:
        lines.append("## Environment")
        lines.append("")
        for key, values in environment.items():
            if len(values) == 1:
                lines.append(f"- `{key}`: `{values[0]}`")
            else:
                joined = ", ".join(f"`{v}`" for v in values)
                lines.append(f"- `{key}`: {joined}")
        lines.append("")

    lines.append("## Timings")
    lines.append("")
    lines.append("| Metric | n | min ms | p50 ms | mean ms | p95 ms | max ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    metrics = summary.get("metrics") or {}
    for key, label in METRICS:
        if key not in metrics:
            continue
        row = metrics[key]
        lines.append(
            "| {label} | {n} | {min} | {p50} | {mean} | {p95} | {max} |".format(
                label=label,
                n=row["n"],
                min=fmt_ms(row["min"]),
                p50=fmt_ms(row["p50"]),
                mean=fmt_ms(row["mean"]),
                p95=fmt_ms(row["p95"]),
                max=fmt_ms(row["max"]),
            )
        )
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    for run in summary.get("runs") or []:
        run_id = run.get("run_id") or "(no run_id)"
        timestamp = run.get("timestamp_utc") or "(no timestamp)"
        lines.append(f"- `{run_id}` `{timestamp}`: `{run['path']}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="benchmark JSON files or directories")
    parser.add_argument("--json", action="store_true", help="emit machine-readable summary")
    args = parser.parse_args()

    paths = discover(args.inputs)
    if not paths:
        raise SystemExit("no benchmark.json or benchmark.redacted.json files found")

    summary = collect(paths)
    if args.json:
        json.dump(summary, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print(render_markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
