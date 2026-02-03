#!/usr/bin/env python3
"""
analyze_quality_determinism.py — Compare embedding outputs across benchmark runs.

Checks whether embeddings are bit-identical (SHA-256 match) or near-identical
(cosine similarity ~1.0) across multiple runs and environments.

Usage:
    # Compare multiple baseline runs:
    python3 scripts/analyze_quality_determinism.py \\
        --baseline-files baseline_v1.json baseline_v2.json baseline_v3.json

    # Compare baseline vs enclave:
    python3 scripts/analyze_quality_determinism.py \\
        --baseline-files baseline_v3.json \\
        --enclave-files enclave_v3.json

    # Output to file:
    python3 scripts/analyze_quality_determinism.py \\
        --baseline-files baseline_v3.json \\
        --output quality_determinism.json
"""

import argparse
import json
import math
import sys
from typing import Any, Dict, List, Optional


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    return dot / (mag_a * mag_b) if mag_a > 0 and mag_b > 0 else 0.0


def max_abs_diff(a: List[float], b: List[float]) -> float:
    return max((abs(x - y) for x, y in zip(a, b)), default=0.0)


def analyze_group(files: List[str], label: str) -> Optional[Dict[str, Any]]:
    """Analyze determinism within a group of result files."""
    if not files:
        return None

    sha256s = []
    embeddings = []

    for path in files:
        data = load_json(path)
        quality = data.get("quality", {})

        sha = quality.get("embedding_sha256")
        if sha:
            sha256s.append(sha)

        emb = quality.get("embedding")
        if isinstance(emb, list) and len(emb) > 0:
            embeddings.append(emb)

    if not sha256s and not embeddings:
        print(f"[quality] WARNING: No embedding data found in {label} files", file=sys.stderr)
        return None

    unique_sha = list(set(sha256s))
    deterministic = len(unique_sha) <= 1 and len(sha256s) > 0

    result = {
        "num_runs": len(files),
        "files": files,
        "deterministic": deterministic,
        "unique_sha256_count": len(unique_sha),
        "sha256": unique_sha,
    }

    # Pairwise analysis if we have embeddings
    if len(embeddings) >= 2:
        pairwise_cosine = []
        pairwise_max_diff = []
        for i in range(len(embeddings)):
            for j in range(i + 1, len(embeddings)):
                if len(embeddings[i]) == len(embeddings[j]):
                    cos = cosine_similarity(embeddings[i], embeddings[j])
                    mad = max_abs_diff(embeddings[i], embeddings[j])
                    pairwise_cosine.append(cos)
                    pairwise_max_diff.append(mad)

        if pairwise_cosine:
            result["pairwise_cosine_similarity"] = {
                "min": min(pairwise_cosine),
                "max": max(pairwise_cosine),
                "mean": sum(pairwise_cosine) / len(pairwise_cosine),
            }
            result["pairwise_max_abs_diff"] = {
                "min": min(pairwise_max_diff),
                "max": max(pairwise_max_diff),
                "mean": sum(pairwise_max_diff) / len(pairwise_max_diff),
            }

    return result


def analyze_cross_environment(
    baseline_files: List[str], enclave_files: List[str]
) -> Optional[Dict[str, Any]]:
    """Compare embeddings across baseline and enclave environments."""
    if not baseline_files or not enclave_files:
        return None

    baseline_embeddings = []
    enclave_embeddings = []
    baseline_sha = []
    enclave_sha = []

    for path in baseline_files:
        data = load_json(path)
        q = data.get("quality", {})
        emb = q.get("embedding")
        sha = q.get("embedding_sha256")
        if isinstance(emb, list) and len(emb) > 0:
            baseline_embeddings.append(emb)
        if sha:
            baseline_sha.append(sha)

    for path in enclave_files:
        data = load_json(path)
        q = data.get("quality", {})
        emb = q.get("embedding")
        sha = q.get("embedding_sha256")
        if isinstance(emb, list) and len(emb) > 0:
            enclave_embeddings.append(emb)
        if sha:
            enclave_sha.append(sha)

    if not baseline_embeddings or not enclave_embeddings:
        return None

    # Compare all baseline vs all enclave pairs
    cosines = []
    max_diffs = []
    for b_emb in baseline_embeddings:
        for e_emb in enclave_embeddings:
            if len(b_emb) == len(e_emb):
                cosines.append(cosine_similarity(b_emb, e_emb))
                max_diffs.append(max_abs_diff(b_emb, e_emb))

    if not cosines:
        return None

    sha_match = bool(baseline_sha and enclave_sha and set(baseline_sha) == set(enclave_sha))

    min_cos = min(cosines)
    max_diff = max(max_diffs)

    if sha_match:
        verdict = "bit-identical"
    elif min_cos > 0.999999 and max_diff < 1e-6:
        verdict = "near-identical (f32 precision)"
    elif min_cos > 0.999:
        verdict = "similar (minor numerical differences)"
    else:
        verdict = "divergent (investigate)"

    return {
        "sha256_match": sha_match,
        "cosine_similarity": {
            "min": min_cos,
            "max": max(cosines),
            "mean": sum(cosines) / len(cosines),
        },
        "max_abs_diff": {
            "min": min(max_diffs),
            "max": max_diff,
            "mean": sum(max_diffs) / len(max_diffs),
        },
        "verdict": verdict,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze embedding quality determinism across benchmark runs"
    )
    parser.add_argument(
        "--baseline-files",
        nargs="+",
        default=[],
        help="Baseline result JSON files",
    )
    parser.add_argument(
        "--enclave-files",
        nargs="+",
        default=[],
        help="Enclave result JSON files",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file (default: stdout)",
    )
    args = parser.parse_args()

    if not args.baseline_files and not args.enclave_files:
        parser.error("At least one of --baseline-files or --enclave-files is required")

    result: Dict[str, Any] = {
        "benchmark": "quality_determinism",
    }

    baseline_analysis = analyze_group(args.baseline_files, "baseline")
    if baseline_analysis:
        result["baseline"] = baseline_analysis
        result["num_runs"] = baseline_analysis["num_runs"]

    enclave_analysis = analyze_group(args.enclave_files, "enclave")
    if enclave_analysis:
        result["enclave"] = enclave_analysis
        if "num_runs" not in result:
            result["num_runs"] = enclave_analysis["num_runs"]

    cross = analyze_cross_environment(args.baseline_files, args.enclave_files)
    if cross:
        result["cross_environment"] = cross

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output + "\n")
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
