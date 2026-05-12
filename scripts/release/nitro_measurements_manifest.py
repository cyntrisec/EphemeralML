#!/usr/bin/env python3
"""Emit the release manifest consumed by worker.yaml CFN parameters."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


HEX_384 = re.compile(r"^[0-9a-fA-F]{96}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nitro-output", required=True, type=Path)
    parser.add_argument("--eif", required=True, type=Path)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--rootfs-image", required=True)
    parser.add_argument("--eif-oci-ref", required=True)
    parser.add_argument("--out", required=True, type=Path)
    return parser.parse_args()


def extract_json_object(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("nitro-cli output did not contain a JSON object")
    return json.loads(text[start : end + 1])


def measurement(data: dict[str, Any], name: str) -> str:
    candidates = [
        data.get(name),
        data.get(name.lower()),
        data.get("Measurements", {}).get(name),
        data.get("Measurements", {}).get(name.lower()),
        data.get("measurements", {}).get(name),
        data.get("measurements", {}).get(name.lower()),
    ]
    for value in candidates:
        if isinstance(value, str):
            value = value.strip().lower()
            if HEX_384.match(value):
                return value
    raise ValueError(f"missing or invalid {name} SHA-384 measurement in nitro-cli output")


def sha384_file(path: Path) -> str:
    h = hashlib.sha384()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    args = parse_args()
    nitro = extract_json_object(args.nitro_output.read_text(encoding="utf-8"))
    pcr0 = measurement(nitro, "PCR0")
    pcr1 = measurement(nitro, "PCR1")
    pcr2 = measurement(nitro, "PCR2")

    manifest = {
        "schema_version": 1,
        "release_tag": args.release_tag,
        "rootfs_image": args.rootfs_image,
        "eif_oci_ref": args.eif_oci_ref,
        "eif_sha384": sha384_file(args.eif),
        "measurements": {
            "PCR0": pcr0,
            "PCR1": pcr1,
            "PCR2": pcr2,
            "EnclaveImageSha384": pcr0,
        },
        "cloudformation_parameters": {
            "param_EnclaveImageSha384": pcr0,
            "param_EnclavePcr1Sha384": pcr1,
            "param_EnclavePcr2Sha384": pcr2,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
