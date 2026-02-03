#!/usr/bin/env python3
"""
analyze_repro.py — Analyze reproducibility across multiple benchmark runs.

Computes mean, stddev, and coefficient of variation (CV) for key metrics
across N runs of the benchmark suite.

Usage:
    python3 scripts/analyze_repro.py --run-dirs benchmark_results/repro_*/run_*
    python3 scripts/analyze_repro.py --run-dirs run_001/ run_002/ run_003/ --output repro.json
"""

import argparse
import json
import math
import os
import sys
from typing import Any, Dict, List, Optional


def load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[repro] WARNING: Could not load {path}: {e}", file=sys.stderr)
        return None


def extract_metric(data: Dict[str, Any], dotpath: str) -> Optional[float]:
    """Extract a numeric value using dot-separated path, e.g. 'inference.latency_ms.mean'."""
    obj = data
    for key in dotpath.split("."):
        if isinstance(obj, dict) and key in obj:
            obj = obj[key]
        else:
            return None
    if isinstance(obj, (int, float)):
        return float(obj)
    return None


def compute_stats(values: List[float]) -> Dict[str, Any]:
    """Compute mean, stddev, and coefficient of variation."""
    n = len(values)
    if n == 0:
        return {"values": [], "mean": 0.0, "stddev": 0.0, "cv_pct": 0.0, "n": 0}
    mean = sum(values) / n
    if n > 1:
        variance = sum((v - mean) ** 2 for v in values) / (n - 1)
        stddev = math.sqrt(variance)
    else:
        stddev = 0.0
    cv_pct = (stddev / mean * 100.0) if mean > 0 else 0.0
    return {
        "values": [round(v, 4) for v in values],
        "mean": round(mean, 4),
        "stddev": round(stddev, 4),
        "cv_pct": round(cv_pct, 2),
        "n": n,
    }


# Metrics to extract from baseline results
BASELINE_METRICS = [
    ("baseline_inference_mean_ms", "inference.latency_ms.mean"),
    ("baseline_inference_p50_ms", "inference.latency_ms.p50"),
    ("baseline_inference_p95_ms", "inference.latency_ms.p95"),
    ("baseline_inference_p99_ms", "inference.latency_ms.p99"),
    ("baseline_throughput_inf_per_sec", "inference.throughput_inferences_per_sec"),
    ("baseline_cold_start_ms", "stages.cold_start_total_ms"),
    ("baseline_model_load_ms", "stages.model_load_ms"),
    ("baseline_tokenizer_setup_ms", "stages.tokenizer_setup_ms"),
    ("baseline_peak_rss_mb", "memory.peak_rss_mb"),
]

# Metrics to extract from enclave results
ENCLAVE_METRICS = [
    ("enclave_inference_mean_ms", "inference.latency_ms.mean"),
    ("enclave_inference_p50_ms", "inference.latency_ms.p50"),
    ("enclave_inference_p95_ms", "inference.latency_ms.p95"),
    ("enclave_inference_p99_ms", "inference.latency_ms.p99"),
    ("enclave_throughput_inf_per_sec", "inference.throughput_inferences_per_sec"),
    ("enclave_cold_start_ms", "stages.cold_start_total_ms"),
    ("enclave_attestation_ms", "stages.attestation_ms"),
    ("enclave_kms_key_release_ms", "stages.kms_key_release_ms"),
    ("enclave_model_fetch_ms", "stages.model_fetch_ms"),
    ("enclave_peak_rss_mb", "memory.peak_rss_mb"),
]


def main():
    parser = argparse.ArgumentParser(
        description="Analyze benchmark reproducibility across multiple runs"
    )
    parser.add_argument(
        "--run-dirs",
        nargs="+",
        required=True,
        help="Directories containing run results (each should have baseline_results.json and/or enclave_results.json)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file (default: stdout)",
    )
    args = parser.parse_args()

    run_dirs = sorted(args.run_dirs)
    print(f"[repro] Analyzing {len(run_dirs)} runs", file=sys.stderr)

    # Collect metric values across runs
    metric_values: Dict[str, List[float]] = {}

    for run_dir in run_dirs:
        # Try baseline
        baseline_path = os.path.join(run_dir, "baseline_results.json")
        baseline = load_json(baseline_path)
        if baseline:
            for name, dotpath in BASELINE_METRICS:
                val = extract_metric(baseline, dotpath)
                if val is not None:
                    metric_values.setdefault(name, []).append(val)

        # Try enclave
        enclave_path = os.path.join(run_dir, "enclave_results.json")
        enclave = load_json(enclave_path)
        if enclave:
            for name, dotpath in ENCLAVE_METRICS:
                val = extract_metric(enclave, dotpath)
                if val is not None:
                    metric_values.setdefault(name, []).append(val)

    # Compute overhead if both baseline and enclave inference means exist
    baseline_means = metric_values.get("baseline_inference_mean_ms", [])
    enclave_means = metric_values.get("enclave_inference_mean_ms", [])
    if baseline_means and enclave_means and len(baseline_means) == len(enclave_means):
        overheads = [
            ((e - b) / b) * 100.0
            for b, e in zip(baseline_means, enclave_means)
            if b > 0
        ]
        if overheads:
            metric_values["overhead_pct"] = overheads

    # Build result
    metrics_result = {}
    for name, values in sorted(metric_values.items()):
        metrics_result[name] = compute_stats(values)

    result = {
        "benchmark": "reproducibility",
        "num_runs": len(run_dirs),
        "run_dirs": run_dirs,
        "metrics": metrics_result,
    }

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        print(f"[repro] Results written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Print summary table to stderr
    print("\n[repro] Summary:", file=sys.stderr)
    print(f"{'Metric':<45} {'Mean':>10} {'StdDev':>10} {'CV%':>8}", file=sys.stderr)
    print("-" * 75, file=sys.stderr)
    for name, stats in sorted(metrics_result.items()):
        print(
            f"{name:<45} {stats['mean']:>10.4f} {stats['stddev']:>10.4f} {stats['cv_pct']:>7.2f}%",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
