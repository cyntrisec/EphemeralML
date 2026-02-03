#!/usr/bin/env python3
"""
generate_paper_tables.py — Generate LaTeX table snippets from EphemeralML benchmark JSON.

This is meant to eliminate copy/paste drift between:
  - benchmark_results/*.json
  - docs/ephemeralml_paper.tex

Example:
  python3 scripts/generate_paper_tables.py \\
    --baseline benchmark_results/baseline_v3.json \\
    --enclave benchmark_results/enclave_v3.json \\
    --crypto benchmark_results/crypto_v1.json \\
    --cose benchmark_results/cose_v1.json \\
    --e2e benchmark_results/e2e_v1.json \\
    --concurrent benchmark_results/concurrent_v1.json
"""

from __future__ import annotations

import argparse
import json
import math
from typing import Any, Dict, List, Optional, Tuple


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def overhead_pct(baseline: float, enclave: float) -> str:
    if baseline <= 0:
        return "N/A"
    pct = ((enclave - baseline) / baseline) * 100.0
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}\\%"


def fmt_ms(v: float, decimals: int = 2) -> str:
    return f"{v:.{decimals}f}\\,ms"


def fmt_inf_s(v: float, decimals: int = 1) -> str:
    return f"{v:.{decimals}f}\\,inf/s"


def fmt_mb(v: float) -> str:
    return f"{v:,.0f}\\,MB"


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    return dot / (mag_a * mag_b) if mag_a > 0 and mag_b > 0 else 0.0


def _max_abs_diff(a: List[float], b: List[float]) -> float:
    return max((abs(x - y) for x, y in zip(a, b)), default=0.0)


def _quality_metrics(baseline: Dict[str, Any], enclave: Dict[str, Any]) -> Optional[Tuple[int, float, float, str]]:
    bq = baseline.get("quality", {}) or {}
    eq = enclave.get("quality", {}) or {}

    b_full = bq.get("embedding")
    e_full = eq.get("embedding")
    if isinstance(b_full, list) and isinstance(e_full, list) and len(b_full) == len(e_full) and len(b_full) > 0:
        cos = _cosine_similarity(b_full, e_full)
        mad = _max_abs_diff(b_full, e_full)
        return (len(b_full), cos, mad, "full")

    b8 = bq.get("embedding_first_8")
    e8 = eq.get("embedding_first_8")
    if isinstance(b8, list) and isinstance(e8, list) and len(b8) == len(e8) and len(b8) > 0:
        cos = _cosine_similarity(b8, e8)
        mad = _max_abs_diff(b8, e8)
        return (len(b8), cos, mad, "first_8")

    return None


def emit_inference_table(baseline: Dict[str, Any], enclave: Dict[str, Any]) -> str:
    b_lat = baseline["inference"]["latency_ms"]
    e_lat = enclave["inference"]["latency_ms"]
    b_tp = baseline["inference"]["throughput_inferences_per_sec"]
    e_tp = enclave["inference"]["throughput_inferences_per_sec"]
    b_rss = baseline["memory"]["peak_rss_mb"]
    e_rss = enclave["memory"]["peak_rss_mb"]

    lines = []
    lines.append("% === Inference latency comparison (generated) ===")
    lines.append("\\begin{tabular}{lrrr}")
    lines.append("\\hline")
    lines.append("\\textbf{Metric} & \\textbf{Bare Metal} & \\textbf{Enclave} & \\textbf{Overhead} \\\\")
    lines.append("\\hline")
    lines.append(
        f"Mean latency     & {fmt_ms(b_lat['mean'])}  & {fmt_ms(e_lat['mean'])}  & {overhead_pct(b_lat['mean'], e_lat['mean'])} \\\\"
    )
    lines.append(
        f"P95 latency      & {fmt_ms(b_lat['p95'])}  & {fmt_ms(e_lat['p95'])}  & {overhead_pct(b_lat['p95'], e_lat['p95'])} \\\\"
    )
    lines.append(
        f"Throughput       & {fmt_inf_s(b_tp)} & {fmt_inf_s(e_tp)} & {overhead_pct(b_tp, e_tp)} \\\\"
    )
    lines.append(
        f"Peak RSS         & {fmt_mb(b_rss)}    & {fmt_mb(e_rss)} & {overhead_pct(b_rss, e_rss)} \\\\"
    )
    lines.append("\\hline")
    lines.append("\\end{tabular}")
    return "\n".join(lines)


def emit_cold_start_table(enclave: Dict[str, Any]) -> str:
    s = enclave["stages"]
    lines = []
    lines.append("% === Cold start breakdown (generated) ===")
    lines.append("\\begin{tabular}{lr}")
    lines.append("\\hline")
    lines.append("\\textbf{Phase} & \\textbf{Latency} \\\\")
    lines.append("\\hline")
    lines.append(f"NSM attestation generation & {fmt_ms(s['attestation_ms'], 0)} \\\\")
    lines.append(f"KMS key release            & {fmt_ms(s['kms_key_release_ms'], 0)} \\\\")
    lines.append(f"S3 model fetch (via VSock) & {fmt_ms(s['model_fetch_ms'], 0)} \\\\")
    lines.append(f"Model decryption           & {fmt_ms(s['model_decrypt_ms'], 0)} \\\\")
    lines.append(f"Model load (Candle)        & {fmt_ms(s['model_load_ms'], 0)} \\\\")
    lines.append(f"Tokenizer setup            & {fmt_ms(s['tokenizer_setup_ms'], 0)} \\\\")
    lines.append("\\hline")
    lines.append(f"\\textbf{{Total}}             & \\textbf{{{fmt_ms(s['cold_start_total_ms'], 0)}}} \\\\")
    lines.append("\\hline")
    lines.append("\\end{tabular}")
    return "\n".join(lines)


def emit_quality_line(baseline: Dict[str, Any], enclave: Dict[str, Any]) -> str:
    qm = _quality_metrics(baseline, enclave)
    if qm is None:
        return "% Quality: unavailable (no embeddings in results)"
    dims, cos, mad, kind = qm
    if kind == "full":
        return f"% Quality (full embedding, dim={dims}): cosine={cos:.12f}, max_abs_diff={mad:.3e}"
    return f"% Quality (first {dims} dims only): cosine={cos:.12f}, max_abs_diff={mad:.3e}"


def emit_input_scaling_table(data: Dict[str, Any]) -> str:
    sizes = data.get("sizes", [])
    fit = data.get("scaling_fit", {})

    lines = []
    lines.append("% === Input size scaling (generated) ===")
    lines.append("\\begin{tabular}{rrrrrr}")
    lines.append("\\hline")
    lines.append("\\textbf{Tokens} & \\textbf{Mean} & \\textbf{P50} & \\textbf{P95} & \\textbf{P99} & \\textbf{Min} \\\\")
    lines.append("\\hline")

    for s in sizes:
        lat = s.get("latency_ms", {})
        lines.append(
            f"{s.get('actual_tokens', '?')} & "
            f"{fmt_ms(lat.get('mean', 0))} & "
            f"{fmt_ms(lat.get('p50', 0))} & "
            f"{fmt_ms(lat.get('p95', 0))} & "
            f"{fmt_ms(lat.get('p99', 0))} & "
            f"{fmt_ms(lat.get('min', 0))} \\\\"
        )

    lines.append("\\hline")
    lines.append("\\end{tabular}")

    if fit:
        base = fit.get("base_overhead_ms", 0)
        per_tok = fit.get("per_token_ms", 0)
        lines.append(f"% Linear fit: latency = {base:.2f}ms + {per_tok:.4f}ms/token")

    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--enclave", required=True)
    ap.add_argument("--crypto", default=None)
    ap.add_argument("--cose", default=None)
    ap.add_argument("--e2e", default=None)
    ap.add_argument("--concurrent", default=None)
    ap.add_argument("--input-scaling", default=None)
    args = ap.parse_args()

    baseline = load_json(args.baseline)
    enclave = load_json(args.enclave)

    print(emit_inference_table(baseline, enclave))
    print()
    print(emit_cold_start_table(enclave))
    print()
    print(emit_quality_line(baseline, enclave))

    if args.input_scaling:
        print()
        print(emit_input_scaling_table(load_json(args.input_scaling)))

    # Extra files are intentionally not emitted as full LaTeX tables yet (kept minimal).
    for label, path in [
        ("crypto", args.crypto),
        ("cose", args.cose),
        ("e2e", args.e2e),
        ("concurrent", args.concurrent),
    ]:
        if path:
            data = load_json(path)
            print(f"% Loaded {label} from {path} (benchmark={data.get('benchmark','unknown')})")


if __name__ == "__main__":
    main()

