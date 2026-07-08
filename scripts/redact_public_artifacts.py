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
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_TARGETS = (
    Path("evidence/publication-airv1-20260228"),
    Path("evidence/hardening-v050-20260315T140324Z"),
    Path("evidence/benchmarks"),
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

# Raw/private evidence is the recovery source for a publication bundle. Never
# rewrite it implicitly when a parent directory is passed to this tool.
SKIPPED_DIRECTORY_NAMES = {"raw", "private"}


@dataclass(frozen=True)
class Replacement:
    pattern: re.Pattern[str]
    value: str


# Match the UUID-shaped project-name convention used by historical runs without
# embedding any live project identifier in the publication tool itself.
_GCP_UUID_STYLE_PROJECT = (
    r"project-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{3}"
)
_CYNTRISEC_EMAIL = r"[A-Za-z0-9._%+-]+@cyntrisec\.com"


REPLACEMENTS = (
    Replacement(
        re.compile(rf"ephemeralml-models-{_GCP_UUID_STYLE_PROJECT}"),
        "redacted-model-bucket",
    ),
    Replacement(
        re.compile(rf"\b{_GCP_UUID_STYLE_PROJECT}\b"),
        "gcp-project-redacted",
    ),
    Replacement(
        re.compile(r"//iam\.googleapis\.com/projects/\d{6,}/locations/"),
        "//iam.googleapis.com/projects/gcp-project-number-redacted/locations/",
    ),
    Replacement(
        re.compile(rf"\b{_CYNTRISEC_EMAIL}\b", re.IGNORECASE),
        "operator@example.invalid",
    ),
    Replacement(
        re.compile(r"s3://(?!redacted-private-bucket\b)[A-Za-z0-9._-]+"),
        "s3://redacted-private-bucket",
    ),
    Replacement(
        re.compile(r"gs://(?!redacted-(?:private|model)-bucket\b)[A-Za-z0-9._-]+"),
        "gs://redacted-private-bucket",
    ),
    Replacement(
        re.compile(r"\b\d{12}\b"),
        "aws-account-redacted",
    ),
    Replacement(
        re.compile(r"/home/[A-Za-z0-9._-]+/[^ \n\r\t\"'`<>()\[\]{},;]*"),
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
    re.compile(rf"\b{_GCP_UUID_STYLE_PROJECT}\b"),
    re.compile(r"//iam\.googleapis\.com/projects/\d{6,}/locations/"),
    re.compile(rf"\b{_CYNTRISEC_EMAIL}\b", re.IGNORECASE),
    re.compile(r"s3://(?!redacted-private-bucket\b)[A-Za-z0-9._-]+"),
    re.compile(r"gs://(?!redacted-(?:private|model)-bucket\b)[A-Za-z0-9._-]+"),
    re.compile(r"\b\d{12}\b"),
    re.compile(r"/home/[A-Za-z0-9._-]+/"),
    re.compile(r"/tmp/tmp[.A-Za-z0-9_-]+"),
    re.compile(r"\bi-[0-9a-f]{17}-enc[0-9a-f]{16,}\b"),
    re.compile(r"\bi-[0-9a-f]{17}\b"),
)


# Public IPv4 redaction is context-aware: a syntactic dotted-quad is only
# replaced when it parses as a valid address AND falls outside every reserved,
# private, loopback, link-local (incl. the cloud metadata endpoint), or
# documentation range below. This preserves internal 10.x deploy IPs, the
# 169.254.169.254 metadata IP, and RFC 5737 doc IPs, and it is idempotent
# because the placeholder itself lives in the preserved 203.0.113.0/24 block.
# We use an explicit network list rather than ipaddress.is_global because the
# stdlib's treatment of the RFC 5737 documentation ranges differs across
# Python versions.
_PUBLIC_IP_PLACEHOLDER = "203.0.113.10"  # RFC 5737 TEST-NET-3 (documentation)

_PRESERVED_IP_NETS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local (incl. 169.254.169.254 metadata)
        "172.16.0.0/12",
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "192.88.99.0/24",  # 6to4 relay anycast
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3 (contains the placeholder)
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved (incl. 255.255.255.255)
    )
)

_IP_CANDIDATE = re.compile(r"(?<![\w.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w.])")


def _is_public_ipv4(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False  # octet > 255: not an address (e.g. a version/section number)
    return not any(ip in net for net in _PRESERVED_IP_NETS)


def redact_public_ipv4(value: str) -> str:
    def _sub(match: re.Match[str]) -> str:
        raw = match.group(1)
        return _PUBLIC_IP_PLACEHOLDER if _is_public_ipv4(raw) else raw

    return _IP_CANDIDATE.sub(_sub, value)


def line_has_public_ipv4(line: str) -> bool:
    return any(_is_public_ipv4(m.group(1)) for m in _IP_CANDIDATE.finditer(line))


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
            if root.name in SKIPPED_DIRECTORY_NAMES:
                continue
            for path in sorted(root.rglob("*")):
                relative_parts = path.relative_to(root).parts[:-1]
                if any(part in SKIPPED_DIRECTORY_NAMES for part in relative_parts):
                    continue
                if path.is_file() and is_text_file(path):
                    yield path


def redact_text(value: str) -> str:
    out = value
    for replacement in REPLACEMENTS:
        out = replacement.pattern.sub(replacement.value, out)
    out = redact_public_ipv4(out)
    return out


def redact_file(path: Path) -> bool:
    # newline="" disables universal-newline translation so redaction only
    # rewrites the matched tokens and leaves original line endings (incl. the
    # embedded CRs in terminal-progress logs) byte-for-byte intact.
    try:
        with open(path, "r", encoding="utf-8", newline="") as handle:
            before = handle.read()
    except UnicodeDecodeError:
        return False
    after = redact_text(before)
    if after == before:
        return False
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(after)
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
        "Cloud project, bucket, KMS, local path, operator email, public IPv4 "
        "addresses, and Nitro enclave identifiers were redacted for public "
        "repository publication."
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
                "emails, public IPv4 addresses, and Nitro instance/enclave",
                "identifiers were replaced with stable placeholders.",
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
            if any(pattern.search(line) for pattern in BLOCKED_PATTERNS) or line_has_public_ipv4(line):
                # Never echo the matching content: this command is commonly run
                # in CI, where doing so would copy the identifier into logs.
                hits.append(f"{path}:{idx}:sensitive identifier remains")
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
