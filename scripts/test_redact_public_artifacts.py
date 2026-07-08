#!/usr/bin/env python3
"""Regression tests for public-artifact redaction."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from redact_public_artifacts import (  # noqa: E402
    BLOCKED_PATTERNS,
    iter_text_files,
    line_has_public_ipv4,
    redact_text,
    scan_blocked,
)


class RedactPublicArtifactsTests(unittest.TestCase):
    def test_redacts_cloud_and_operator_identifiers_without_literal_allowlist(self) -> None:
        project = "project-01234567-89ab-cdef-012"
        source = "\n".join(
            [
                f"project={project}",
                f"model=gs://ephemeralml-models-{project}/model.bin",
                f"image=us-docker.pkg.dev/{project}/repo/image@sha256:abcd",
                "contact=reviewer@cyntrisec.com",
                "role=arn:aws:iam::111122223333:role/Verifier",
                "evidence=s3://private-evidence-bucket/run/manifest.json",
                "path=/home/alice/work/run/output.json",
                "host=8.8.8.8",
                "instance=i-0123456789abcdef0",
            ]
        )

        redacted = redact_text(source)

        self.assertNotIn(project, redacted)
        self.assertNotIn("reviewer@cyntrisec.com", redacted)
        self.assertNotIn("111122223333", redacted)
        self.assertNotIn("private-evidence-bucket", redacted)
        self.assertNotIn("/home/alice/", redacted)
        self.assertNotIn("8.8.8.8", redacted)
        self.assertNotIn("i-0123456789abcdef0", redacted)
        self.assertEqual(redact_text(redacted), redacted)
        self.assertFalse(any(pattern.search(redacted) for pattern in BLOCKED_PATTERNS))
        self.assertFalse(line_has_public_ipv4(redacted))

    def test_preserves_private_metadata_and_documentation_addresses(self) -> None:
        source = "10.0.0.5 169.254.169.254 192.0.2.10 198.51.100.20 203.0.113.30"
        self.assertEqual(redact_text(source), source)

    def test_local_path_redaction_preserves_closing_delimiter(self) -> None:
        source = "Compiling crate (/home/alice/work/crate)"

        self.assertEqual(
            redact_text(source),
            "Compiling crate (<redacted-local-path>)",
        )

    def test_check_output_does_not_repeat_sensitive_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.log"
            sensitive_value = "reviewer@cyntrisec.com"
            path.write_text(f"contact={sensitive_value}\n", encoding="utf-8")

            hits = scan_blocked([path])

        self.assertEqual(len(hits), 1)
        self.assertNotIn(sensitive_value, hits[0])
        self.assertIn("sensitive identifier remains", hits[0])

    def test_parent_target_skips_raw_and_private_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            publishable = root / "redacted" / "run.log"
            raw = root / "raw" / "run.log"
            private = root / "private" / "run.log"
            for path in (publishable, raw, private):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("evidence\n", encoding="utf-8")

            discovered = set(iter_text_files([root]))

        self.assertEqual(discovered, {publishable})


if __name__ == "__main__":
    unittest.main()
