#!/usr/bin/env python3
"""
generate_model_scaling_table.py — Generate a compact LaTeX table comparing overhead across models.

Usage:
  python3 scripts/generate_model_scaling_table.py \
    --pair minilm-l6  path/to/baseline.json path/to/enclave.json \
    --pair minilm-l12 path/to/baseline.json path/to/enclave.json \
    --pair bert-base  path/to/baseline.json path/to/enclave.json
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Tuple


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def overhead_pct(baseline: float, enclave: float) -> str:
    if baseline <= 0:
        return "N/A"
    pct = ((enclave - baseline) / baseline) * 100.0
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}\\%"


def fmt_ms(v: float) -> str:
    return f"{v:.2f}\\,ms"


def fmt_params(v: int) -> str:
    # Keep it simple: show M parameters with one decimal.
    return f"{v / 1_000_000.0:.1f}M"


def extract_row(model_id: str, baseline: Dict[str, Any], enclave: Dict[str, Any]) -> Tuple:
    model_name = enclave.get("model") or baseline.get("model") or model_id
    params = int(enclave.get("model_params") or baseline.get("model_params") or 0)
    embed_dim = int(enclave.get("embedding_dim") or baseline.get("quality", {}).get("embedding_dim") or 0)

    b_mean = float(baseline.get("inference", {}).get("latency_ms", {}).get("mean", 0.0))
    e_mean = float(enclave.get("inference", {}).get("latency_ms", {}).get("mean", 0.0))
    oh = overhead_pct(b_mean, e_mean)

    return (model_name, model_id, params, embed_dim, b_mean, e_mean, oh)


def emit_table(rows: List[Tuple]) -> str:
    lines: List[str] = []
    lines.append("% === Overhead vs model size (generated) ===")
    lines.append("\\begin{tabular}{llrrrrr}")
    lines.append("\\hline")
    lines.append("\\textbf{Model} & \\textbf{ID} & \\textbf{Params} & \\textbf{Dim} & \\textbf{Bare} & \\textbf{Enclave} & \\textbf{Overhead}\\\\")
    lines.append("\\hline")
    for model_name, model_id, params, embed_dim, b_mean, e_mean, oh in rows:
        params_s = fmt_params(params) if params else "?"
        dim_s = str(embed_dim) if embed_dim else "?"
        lines.append(
            f"{model_name} & {model_id} & {params_s} & {dim_s} & {fmt_ms(b_mean)} & {fmt_ms(e_mean)} & {oh}\\\\"
        )
    lines.append("\\hline")
    lines.append("\\end{tabular}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--pair",
        action="append",
        nargs=3,
        metavar=("MODEL_ID", "BASELINE_JSON", "ENCLAVE_JSON"),
        required=True,
        help="Add a model pair (repeatable).",
    )
    args = ap.parse_args()

    rows: List[Tuple] = []
    for model_id, baseline_path, enclave_path in args.pair:
        b = load_json(baseline_path)
        e = load_json(enclave_path)
        rows.append(extract_row(model_id, b, e))

    # Sort by parameter count (fallback: keep input order)
    if all(r[2] > 0 for r in rows):
        rows.sort(key=lambda r: r[2])

    print(emit_table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

