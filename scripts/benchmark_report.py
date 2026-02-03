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
        ("tokenizer_setup_ms", "Tokenizer Setup"),
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
        lines.append(f"| **Upload Throughput** | **{e_vsock.get('upload_throughput_mbps', 0.0):.1f} MB/s** |")
        lines.append("")

    # Quality verification
    b_qual = baseline.get("quality", {})
    e_qual = enclave.get("quality", {})

    b_full = b_qual.get("embedding", None)
    e_full = e_qual.get("embedding", None)
    b_sha = b_qual.get("embedding_sha256", None)
    e_sha = e_qual.get("embedding_sha256", None)

    def cosine_similarity(a: list, b: list) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = sum(x * x for x in a) ** 0.5
        mag_b = sum(y * y for y in b) ** 0.5
        return dot / (mag_a * mag_b) if mag_a > 0 and mag_b > 0 else 0.0

    def max_abs_diff(a: list, b: list) -> float:
        return max((abs(x - y) for x, y in zip(a, b)), default=0.0)

    def is_float_list(v) -> bool:
        return isinstance(v, list) and all(isinstance(x, (int, float)) for x in v)

    if is_float_list(b_full) and is_float_list(e_full) and len(b_full) == len(e_full) and len(b_full) > 0:
        cos_sim = cosine_similarity(b_full, e_full)
        mad = max_abs_diff(b_full, e_full)
        bit_identical = (b_sha is not None and e_sha is not None and b_sha == e_sha) or (b_full == e_full)

        lines.append("## Output Quality Verification")
        lines.append("")
        lines.append(f"**Reference text:** \"{b_qual.get('reference_text', 'N/A')}\"")
        lines.append(f"**Embedding dimension:** {b_qual.get('embedding_dim', 'N/A')}")
        lines.append(f"**Cosine similarity (full embedding):** {cos_sim:.15f}")
        lines.append(f"**Max abs diff (full embedding):** {mad:.3e}")
        lines.append(f"**Bit-identical (SHA-256):** {'yes' if bit_identical else 'no'}")
        lines.append("")

        if bit_identical:
            lines.append("Enclave produces **bit-identical** embeddings to bare metal.")
        elif cos_sim > 0.999999 and mad < 1e-6:
            lines.append("Enclave produces **near-identical** embeddings (tiny FP-level differences).")
        elif cos_sim > 0.999:
            lines.append("WARNING: Embeddings are similar but not identical (cosine sim < 0.999999).")
        else:
            lines.append("ERROR: Significant embedding divergence detected. Investigate model loading / numeric determinism.")
        lines.append("")
    else:
        b_emb = b_qual.get("embedding_first_8", [])
        e_emb = e_qual.get("embedding_first_8", [])
        if is_float_list(b_emb) and is_float_list(e_emb) and len(b_emb) == len(e_emb) and len(b_emb) > 0:
            cos_sim = cosine_similarity(b_emb, e_emb)
            mad = max_abs_diff(b_emb, e_emb)

            lines.append("## Output Quality Verification")
            lines.append("")
            lines.append(f"**Reference text:** \"{b_qual.get('reference_text', 'N/A')}\"")
            lines.append(f"**Embedding dimension:** {b_qual.get('embedding_dim', 'N/A')}")
            lines.append(f"**Cosine similarity (first 8 dims):** {cos_sim:.15f}")
            lines.append(f"**Max abs diff (first 8 dims):** {mad:.3e}")
            lines.append("")
            lines.append("NOTE: Only the first 8 dimensions were recorded in these results; this is a sanity check, not a full-vector equivalence proof.")
            lines.append("")

    # Cost analysis
    AWS_PRICING = {
        "m6i.xlarge": 0.192,
        "c6i.xlarge": 0.170,
        "c6i.2xlarge": 0.340,
        "m6i.2xlarge": 0.384,
    }

    hardware = enclave.get("hardware", "unknown")
    b_tp = baseline.get("inference", {}).get("throughput_inferences_per_sec", 0.0)
    e_tp = enclave.get("inference", {}).get("throughput_inferences_per_sec", 0.0)
    price_hr = AWS_PRICING.get(hardware, 0.0)

    if price_hr > 0 and (b_tp > 0 or e_tp > 0):
        lines.append("## Cost Analysis")
        lines.append("")
        lines.append(f"**Instance:** {hardware} @ ${price_hr:.3f}/hr (on-demand, us-east-1)")
        lines.append("")
        lines.append("| Metric | Bare Metal | Enclave |")
        lines.append("|--------|-----------|---------|")
        if b_tp > 0:
            b_inf_hr = b_tp * 3600
            b_cost_1k = (price_hr / b_inf_hr) * 1000
            b_cost_1m = (price_hr / b_inf_hr) * 1_000_000
        else:
            b_inf_hr = b_cost_1k = b_cost_1m = 0.0
        if e_tp > 0:
            e_inf_hr = e_tp * 3600
            e_cost_1k = (price_hr / e_inf_hr) * 1000
            e_cost_1m = (price_hr / e_inf_hr) * 1_000_000
        else:
            e_inf_hr = e_cost_1k = e_cost_1m = 0.0
        lines.append(f"| Inferences/hour | {b_inf_hr:,.0f} | {e_inf_hr:,.0f} |")
        lines.append(f"| Cost per 1K inferences | ${b_cost_1k:.4f} | ${e_cost_1k:.4f} |")
        lines.append(f"| Cost per 1M inferences | ${b_cost_1m:.2f} | ${e_cost_1m:.2f} |")
        if e_cost_1k > 0 and b_cost_1k > 0:
            multiplier = e_cost_1k / b_cost_1k
            lines.append(f"| Enclave cost multiplier | — | {multiplier:.2f}x |")
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

    if price_hr > 0 and e_tp > 0:
        lines.append(f"- **Cost per 1M inferences:** ${e_cost_1m:.2f} (enclave on {hardware})")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by `scripts/benchmark_report.py`*")
    lines.append("")

    return "\n".join(lines)


def generate_crypto_report(crypto: dict) -> str:
    """Generate markdown section for crypto primitives benchmark."""
    lines = []
    lines.append("")
    lines.append("## Security Primitives Overhead (Tier 4)")
    lines.append("")

    # HPKE section
    hpke = crypto.get("hpke", {})
    setup = hpke.get("session_setup_ms", {})
    keygen = hpke.get("x25519_keygen_ms", {})
    lines.append("### HPKE Session Setup")
    lines.append("")
    lines.append("| Operation | Mean | P50 | P95 | P99 |")
    lines.append("|-----------|------|-----|-----|-----|")
    if setup:
        lines.append(f"| Full session setup (both sides) | {setup.get('mean', 0):.4f}ms | {setup.get('p50', 0):.4f}ms | {setup.get('p95', 0):.4f}ms | {setup.get('p99', 0):.4f}ms |")
    if keygen:
        lines.append(f"| X25519 keypair generation | {keygen.get('mean', 0):.4f}ms | {keygen.get('p50', 0):.4f}ms | {keygen.get('p95', 0):.4f}ms | {keygen.get('p99', 0):.4f}ms |")
    lines.append("")

    # HPKE encrypt/decrypt
    enc_dec = hpke.get("encrypt_decrypt", {})
    if enc_dec:
        lines.append("### HPKE Encrypt/Decrypt Latency")
        lines.append("")
        lines.append("| Payload | Encrypt Mean | Decrypt Mean | Total |")
        lines.append("|---------|-------------|-------------|-------|")
        for size_label in ["64B", "1KB", "64KB", "1MB"]:
            data = enc_dec.get(size_label, {})
            enc = data.get("encrypt", {})
            dec = data.get("decrypt", {})
            enc_mean = enc.get("mean", 0)
            dec_mean = dec.get("mean", 0)
            total = enc_mean + dec_mean
            lines.append(f"| {size_label} | {enc_mean:.4f}ms | {dec_mean:.4f}ms | {total:.4f}ms |")
        lines.append("")

    # Receipt section
    receipt = crypto.get("receipt", {})
    ed_keygen = receipt.get("ed25519_keygen_ms", {})
    sign = receipt.get("sign_ms", {})
    verify = receipt.get("verify_ms", {})
    cbor = receipt.get("canonical_encoding", {})

    lines.append("### Receipt Generation & Verification")
    lines.append("")
    lines.append("| Operation | Mean | P50 | P95 | P99 |")
    lines.append("|-----------|------|-----|-----|-----|")
    if ed_keygen:
        lines.append(f"| Ed25519 keypair generation | {ed_keygen.get('mean', 0):.4f}ms | {ed_keygen.get('p50', 0):.4f}ms | {ed_keygen.get('p95', 0):.4f}ms | {ed_keygen.get('p99', 0):.4f}ms |")
    if sign:
        lines.append(f"| Receipt sign (CBOR + Ed25519) | {sign.get('mean', 0):.4f}ms | {sign.get('p50', 0):.4f}ms | {sign.get('p95', 0):.4f}ms | {sign.get('p99', 0):.4f}ms |")
    if verify:
        lines.append(f"| Receipt verify | {verify.get('mean', 0):.4f}ms | {verify.get('p50', 0):.4f}ms | {verify.get('p95', 0):.4f}ms | {verify.get('p99', 0):.4f}ms |")
    if cbor:
        cbor_lat = cbor.get("latency", {})
        enc_size = cbor.get("encoding_size_bytes", 0)
        lines.append(f"| CBOR canonical encoding ({enc_size}B) | {cbor_lat.get('mean', 0):.4f}ms | {cbor_lat.get('p50', 0):.4f}ms | {cbor_lat.get('p95', 0):.4f}ms | {cbor_lat.get('p99', 0):.4f}ms |")
    lines.append("")

    # Per-inference crypto budget
    if sign and enc_dec:
        enc_1kb = enc_dec.get("1KB", {}).get("encrypt", {}).get("mean", 0)
        dec_1kb = enc_dec.get("1KB", {}).get("decrypt", {}).get("mean", 0)
        sign_mean = sign.get("mean", 0)
        total_crypto = enc_1kb + dec_1kb + sign_mean
        lines.append("### Per-Inference Crypto Budget (1KB payload)")
        lines.append("")
        lines.append(f"| Component | Cost |")
        lines.append(f"|-----------|------|")
        lines.append(f"| HPKE decrypt (request) | {dec_1kb:.4f}ms |")
        lines.append(f"| Receipt sign | {sign_mean:.4f}ms |")
        lines.append(f"| HPKE encrypt (response) | {enc_1kb:.4f}ms |")
        lines.append(f"| **Total crypto overhead** | **{total_crypto:.4f}ms** |")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="EphemeralML Benchmark Report Generator")
    parser.add_argument("--baseline", required=True, help="Path to baseline_results.json")
    parser.add_argument("--enclave", required=True, help="Path to enclave_results.json")
    parser.add_argument("--crypto", default=None, help="Path to crypto benchmark results JSON")
    parser.add_argument("--output", default=None, help="Output markdown file (default: stdout)")
    args = parser.parse_args()

    baseline = load_results(args.baseline)
    enclave = load_results(args.enclave)
    crypto = load_results(args.crypto) if args.crypto else None

    report = generate_report(baseline, enclave)
    if crypto:
        report += generate_crypto_report(crypto)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
