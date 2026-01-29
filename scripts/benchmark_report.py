#!/usr/bin/env python3
"""
benchmark_report.py — Analyze EphemeralML benchmark results and generate comparison report.

Reads baseline_results.json and enclave_results.json, computes overhead percentages,
and generates a markdown report.

Usage:
    python3 benchmark_report.py --baseline baseline_results.json --enclave enclave_results.json [--output report.md]
"""

import argparse
import json
import sys


def load_results(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def overhead_pct(baseline: float, enclave: float) -> str:
    """Compute overhead percentage. Returns formatted string."""
    if baseline <= 0:
        return "N/A"
    pct = ((enclave - baseline) / baseline) * 100.0
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}%"


def fmt_ms(val: float) -> str:
    if val == 0.0:
        return "N/A"
    return f"{val:.2f}ms"


def generate_report(baseline: dict, enclave: dict) -> str:
    lines = []
    lines.append("# EphemeralML Benchmark Report")
    lines.append("")
    lines.append(f"**Model:** {enclave.get('model', 'unknown')}")
    lines.append(f"**Hardware:** {enclave.get('hardware', 'unknown')}")
    lines.append(f"**Commit:** {enclave.get('commit', 'unknown')}")
    lines.append(f"**Timestamp:** {enclave.get('timestamp', 'unknown')}")
    lines.append(f"**Iterations:** {enclave.get('inference', {}).get('num_iterations', 'unknown')}")
    lines.append("")

    # Stage timing comparison
    lines.append("## Stage Timing")
    lines.append("")
    lines.append("| Stage | Bare Metal | Enclave | Overhead |")
    lines.append("|-------|-----------|---------|----------|")

    b_stages = baseline.get("stages", {})
    e_stages = enclave.get("stages", {})

    stage_keys = [
        ("attestation_ms", "Attestation"),
        ("kms_key_release_ms", "KMS Key Release"),
        ("model_fetch_ms", "Model Fetch"),
        ("model_decrypt_ms", "Model Decrypt"),
        ("model_load_ms", "Model Load"),
        ("cold_start_total_ms", "Cold Start Total"),
    ]

    for key, label in stage_keys:
        bv = b_stages.get(key, 0.0)
        ev = e_stages.get(key, 0.0)
        oh = overhead_pct(bv, ev) if bv > 0 else ("N/A (enclave-only)" if ev > 0 else "N/A")
        lines.append(f"| {label} | {fmt_ms(bv)} | {fmt_ms(ev)} | {oh} |")

    lines.append("")

    # Inference latency comparison
    lines.append("## Inference Latency")
    lines.append("")
    lines.append("| Percentile | Bare Metal | Enclave | Overhead |")
    lines.append("|-----------|-----------|---------|----------|")

    b_lat = baseline.get("inference", {}).get("latency_ms", {})
    e_lat = enclave.get("inference", {}).get("latency_ms", {})

    for key, label in [("mean", "Mean"), ("p50", "P50"), ("p95", "P95"), ("p99", "P99"), ("min", "Min"), ("max", "Max")]:
        bv = b_lat.get(key, 0.0)
        ev = e_lat.get(key, 0.0)
        oh = overhead_pct(bv, ev)
        lines.append(f"| {label} | {fmt_ms(bv)} | {fmt_ms(ev)} | {oh} |")

    b_tp = baseline.get("inference", {}).get("throughput_inferences_per_sec", 0.0)
    e_tp = enclave.get("inference", {}).get("throughput_inferences_per_sec", 0.0)
    tp_oh = overhead_pct(b_tp, e_tp)
    lines.append(f"| Throughput | {b_tp:.1f} inf/s | {e_tp:.1f} inf/s | {tp_oh} |")

    lines.append("")

    # Memory comparison
    lines.append("## Memory Usage")
    lines.append("")
    lines.append("| Metric | Bare Metal | Enclave | Overhead |")
    lines.append("|--------|-----------|---------|----------|")

    b_mem = baseline.get("memory", {})
    e_mem = enclave.get("memory", {})

    bv = b_mem.get("peak_rss_mb", 0.0)
    ev = e_mem.get("peak_rss_mb", 0.0)
    lines.append(f"| Peak RSS | {bv:.1f} MB | {ev:.1f} MB | {overhead_pct(bv, ev)} |")
    lines.append(f"| Model Size | {b_mem.get('model_size_mb', 0.0):.1f} MB | {e_mem.get('model_size_mb', 0.0):.1f} MB | - |")

    lines.append("")

    # VSock metrics (enclave only)
    e_vsock = enclave.get("vsock", {})
    if any(v > 0 for v in e_vsock.values()):
        lines.append("## VSock Communication (Enclave Only)")
        lines.append("")
        lines.append("| Payload Size | RTT |")
        lines.append("|-------------|-----|")
        lines.append(f"| 64 bytes | {fmt_ms(e_vsock.get('rtt_64b_ms', 0.0))} |")
        lines.append(f"| 1 KB | {fmt_ms(e_vsock.get('rtt_1kb_ms', 0.0))} |")
        lines.append(f"| 64 KB | {fmt_ms(e_vsock.get('rtt_64kb_ms', 0.0))} |")
        lines.append(f"| 1 MB | {fmt_ms(e_vsock.get('rtt_1mb_ms', 0.0))} |")
        lines.append(f"| **Throughput** | **{e_vsock.get('throughput_mbps', 0.0):.1f} MB/s** |")
        lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")

    b_mean = b_lat.get("mean", 0.0)
    e_mean = e_lat.get("mean", 0.0)
    if b_mean > 0:
        inf_overhead = ((e_mean - b_mean) / b_mean) * 100.0
        lines.append(f"- **Inference overhead:** {inf_overhead:+.1f}% (enclave vs bare metal)")
    if bv > 0 and ev > 0:
        mem_overhead = ((ev - bv) / bv) * 100.0
        lines.append(f"- **Memory overhead:** {mem_overhead:+.1f}% peak RSS")

    attest_ms = e_stages.get("attestation_ms", 0.0)
    if attest_ms > 0:
        lines.append(f"- **Attestation cost:** {attest_ms:.1f}ms (one-time per session)")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by `scripts/benchmark_report.py`*")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="EphemeralML Benchmark Report Generator")
    parser.add_argument("--baseline", required=True, help="Path to baseline_results.json")
    parser.add_argument("--enclave", required=True, help="Path to enclave_results.json")
    parser.add_argument("--output", default=None, help="Output markdown file (default: stdout)")
    args = parser.parse_args()

    baseline = load_results(args.baseline)
    enclave = load_results(args.enclave)

    report = generate_report(baseline, enclave)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
