#!/usr/bin/env python3
"""Redact public evidence bundles in-place.

This is intentionally narrow. It redacts account-specific cloud metadata from
tracked public evidence/benchmark bundles while preserving receipts,
attestations, timings, verifier outputs, and other proof-bearing content. Binary
artifacts are skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_TARGETS = (
    Path("evidence/publication-airv1-20260228"),
    Path("evidence/hardening-v050-20260315T140324Z"),
    Path("artifacts/benchmarks/aws-nitro-modern-20260225"),
    Path("artifacts/benchmarks/aws-nitro-modern-20260225-clean"),
)

TEXT_SUFFIXES = {
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".tex",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class Replacement:
    pattern: re.Pattern[str]
    value: str


REPLACEMENTS = (
    Replacement(
        re.compile(r"ephemeralml-models-project-d3c20737-eec2-453d-8e5"),
        "redacted-model-bucket",
    ),
    Replacement(
        re.compile(r"project-d3c20737-eec2-453d-8e5"),
        "gcp-project-redacted",
    ),
    Replacement(
        re.compile(r"//iam\.googleapis\.com/projects/\d{6,}/locations/"),
        "//iam.googleapis.com/projects/gcp-project-number-redacted/locations/",
    ),
    Replacement(
        re.compile(r"ephemeralml-cvm@gcp-project-redacted\.iam\.gserviceaccount\.com"),
        "ephemeralml-cvm@gcp-project-redacted.iam.gserviceaccount.com",
    ),
    Replacement(
        re.compile(r"founder@cyntrisec\.com"),
        "operator@example.invalid",
    ),
    Replacement(
        re.compile(r"/home/[A-Za-z0-9._-]+/[^ \n\r\t\"]*"),
        "<redacted-local-path>",
    ),
    Replacement(
        re.compile(r"/tmp/tmp[.A-Za-z0-9_-]+"),
        "/tmp/redacted-temp",
    ),
    Replacement(
        re.compile(r"\bi-[0-9a-f]{17}-enc[0-9a-f]{16,}\b"),
        "i-redacted-enc-redacted",
    ),
    Replacement(
        re.compile(r"\bi-[0-9a-f]{17}\b"),
        "i-redacted",
    ),
)

BLOCKED_PATTERNS = (
    re.compile(r"project-d3c20737-eec2-453d-8e5"),
    re.compile(r"ephemeralml-models-project-d3c20737-eec2-453d-8e5"),
    re.compile(r"us-docker\.pkg\.dev/project-d3c20737-eec2-453d-8e5"),
    re.compile(r"//iam\.googleapis\.com/projects/\d{6,}/locations/"),
    re.compile(r"founder@cyntrisec\.com"),
    re.compile(r"\bi-[0-9a-f]{17}-enc[0-9a-f]{16,}\b"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_text_file(path: Path) -> bool:
    return path.suffix in TEXT_SUFFIXES


def iter_text_files(paths: Iterable[Path]) -> Iterable[Path]:
    for root in paths:
        if root.is_file() and is_text_file(root):
            yield root
        elif root.is_dir():
            for path in sorted(root.rglob("*")):
                if path.is_file() and is_text_file(path):
                    yield path


def redact_text(value: str) -> str:
    out = value
    for replacement in REPLACEMENTS:
        out = replacement.pattern.sub(replacement.value, out)
    return out


def redact_file(path: Path) -> bool:
    try:
        before = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    after = redact_text(before)
    if after == before:
        return False
    path.write_text(after, encoding="utf-8")
    return True


def sibling_artifacts(manifest: Path) -> list[dict[str, object]]:
    artifacts = []
    for path in sorted(manifest.parent.iterdir()):
        if not path.is_file() or path.name == manifest.name:
            continue
        artifacts.append(
            {
                "file": path.name,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return artifacts


def rewrite_artifact_manifest(manifest: Path) -> None:
    generated = "redacted-public-artifact"
    schema_version = 1
    try:
        current = json.loads(manifest.read_text(encoding="utf-8"))
        if isinstance(current, dict):
            generated = str(current.get("generated") or generated)
            schema_version = int(current.get("schema_version") or schema_version)
    except (json.JSONDecodeError, OSError, ValueError):
        pass

    value = {
        "schema_version": schema_version,
        "generated": generated,
        "redacted": True,
        "redaction_note": (
            "Public artifact redaction applied. artifact_manifest.json is "
            "excluded from its own hash list to avoid self-referential hashes."
        ),
        "artifacts": sibling_artifacts(manifest),
    }
    manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def rewrite_publication_manifest(root_manifest: Path) -> None:
    value = json.loads(root_manifest.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        return
    value["redacted"] = True
    value["redaction_note"] = (
        "Cloud project, bucket, KMS, local path, operator email, and Nitro "
        "enclave identifiers were redacted for public repository publication."
    )
    platforms = value.get("platforms")
    if not isinstance(platforms, dict):
        return
    for platform, entry in platforms.items():
        if not isinstance(entry, dict):
            continue
        platform_dir = root_manifest.parent / platform
        if not platform_dir.is_dir():
            continue
        artifacts = []
        for file_path in sorted(platform_dir.iterdir()):
            if not file_path.is_file():
                continue
            artifacts.append(
                {
                    "file": file_path.name,
                    "sha256": sha256_file(file_path),
                    "bytes": file_path.stat().st_size,
                }
            )
        entry["source"] = redact_text(str(entry.get("source") or "redacted-source"))
        entry["artifact_count"] = len(artifacts)
        entry["artifacts"] = artifacts
    root_manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_redaction_note(root: Path) -> None:
    note = root / "REDACTION.md"
    if note.exists():
        return
    note.write_text(
        "\n".join(
            [
                "# Public Evidence Redaction",
                "",
                "This bundle is a redacted public artifact. Live cloud project IDs,",
                "bucket names, KMS resource names, operator-local paths, operator",
                "emails, and Nitro instance/enclave identifiers were replaced with",
                "stable placeholders.",
                "",
                "Cryptographic receipts, attestation binaries, timing files, and",
                "verifier outputs are preserved unless they are text files containing",
                "operator metadata. Redaction-aware manifests in this bundle reflect",
                "the public files after redaction.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def scan_blocked(paths: Iterable[Path]) -> list[str]:
    hits: list[str] = []
    for path in iter_text_files(paths):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in BLOCKED_PATTERNS):
                hits.append(f"{path}:{idx}:{line}")
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=list(DEFAULT_TARGETS),
        help="files/directories to redact (defaults to public evidence bundles)",
    )
    parser.add_argument("--check", action="store_true", help="scan only; do not modify")
    args = parser.parse_args()

    paths = [path for path in args.paths if path.exists()]
    if not paths:
        raise SystemExit("No existing paths to process")

    if args.check:
        hits = scan_blocked(paths)
        if hits:
            print("\n".join(hits))
            return 1
        return 0

    changed = 0
    for path in iter_text_files(paths):
        if redact_file(path):
            changed += 1

    for manifest in sorted(Path(".").glob("**/artifact_manifest.json")):
        if any(manifest.is_relative_to(root) for root in paths if root.is_dir()):
            rewrite_artifact_manifest(manifest)

    publication_manifest = Path("evidence/publication-airv1-20260228/manifest.json")
    if publication_manifest.exists() and any(
        publication_manifest.is_relative_to(root) for root in paths if root.is_dir()
    ):
        rewrite_publication_manifest(publication_manifest)

    for root in paths:
        if root.is_dir() and root.parts and root.parts[0] in {"evidence", "artifacts"}:
            write_redaction_note(root)

    hits = scan_blocked(paths)
    if hits:
        print("\n".join(hits))
        return 1

    print(f"Redacted {changed} text files across {len(paths)} target(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
