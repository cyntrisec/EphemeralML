#!/usr/bin/env python3
"""
AIR v1 vector interoperability test harness.

This script verifies all AIR v1 golden vectors in spec/v1/vectors/ without
depending on the EphemeralML Rust codebase. It performs:

- COSE_Sign1 parsing (CBOR tag 18)
- protected header checks (alg/content_type)
- Ed25519 signature verification over COSE Sig_structure1
- AIR v1 claim validation (Layer 3)
- optional policy checks from vector verify_policy (Layer 4)

Dependencies:
  pip install cbor2 pynacl
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import cbor2
except ImportError as exc:  # pragma: no cover - import guard
    print("Missing dependency: cbor2 (pip install cbor2 pynacl)", file=sys.stderr)
    raise SystemExit(2) from exc

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
except ImportError as exc:  # pragma: no cover - import guard
    print("Missing dependency: pynacl (pip install cbor2 pynacl)", file=sys.stderr)
    raise SystemExit(2) from exc


# CWT / EAT keys
CWT_ISS = 1
CWT_IAT = 6
CWT_CTI = 7
EAT_NONCE = 10
EAT_PROFILE = 265

# AIR private claim keys
AIR_MODEL_ID = -65537
AIR_MODEL_VERSION = -65538
AIR_MODEL_HASH = -65539
AIR_REQUEST_HASH = -65540
AIR_RESPONSE_HASH = -65541
AIR_ATTESTATION_DOC_HASH = -65542
AIR_ENCLAVE_MEASUREMENTS = -65543
AIR_POLICY_VERSION = -65544
AIR_SEQUENCE_NUMBER = -65545
AIR_EXECUTION_TIME_MS = -65546
AIR_MEMORY_PEAK_MB = -65547
AIR_SECURITY_MODE = -65548
AIR_MODEL_HASH_SCHEME = -65549

AIR_PROFILE_URI = "https://spec.cyntrisec.com/air/v1"
ALLOWED_MEASUREMENT_TYPES = {"nitro-pcr", "tdx-mrtd-rtmr"}
ALLOWED_MODEL_HASH_SCHEMES = {"sha256-single", "sha256-concat", "sha256-manifest"}

COSE_TAG_SIGN1 = 18
COSE_ALG_KEY = 1
COSE_CONTENT_TYPE_KEY = 3
COSE_ALG_EDDSA = -8
COSE_CONTENT_TYPE_CWT = 61


@dataclass
class VerifyPolicy:
    expected_nonce: bytes | None = None
    expected_model_hash: bytes | None = None
    expected_platform: str | None = None
    expected_model_id: str | None = None
    max_age_secs: int = 0
    clock_skew_secs: int = 0
    require_nonce: bool = False


@dataclass
class VerificationFailure:
    layer: int
    check: str
    code: str
    reason: str


@dataclass
class VerificationResult:
    ok: bool
    failure: VerificationFailure | None = None


class AirVerifyError(Exception):
    def __init__(self, layer: int, check: str, code: str, reason: str) -> None:
        super().__init__(reason)
        self.failure = VerificationFailure(layer=layer, check=check, code=code, reason=reason)


def fail(layer: int, check: str, code: str, reason: str) -> None:
    raise AirVerifyError(layer=layer, check=check, code=code, reason=reason)


def hex_to_bytes(s: str, field: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_receipt_cose(receipt_bytes: bytes) -> tuple[bytes, dict[Any, Any], bytes, bytes]:
    try:
        decoded = cbor2.loads(receipt_bytes)
    except Exception as exc:
        fail(1, "COSE", "COSE_DECODE_FAILED", f"failed to decode CBOR: {exc}")

    if not isinstance(decoded, cbor2.CBORTag):
        fail(1, "COSE", "COSE_DECODE_FAILED", "top-level CBOR item is not a tag")
    if decoded.tag != COSE_TAG_SIGN1:
        fail(1, "COSE", "COSE_DECODE_FAILED", f"expected tag 18, got tag {decoded.tag}")

    value = decoded.value
    if not isinstance(value, list) or len(value) != 4:
        fail(1, "COSE", "COSE_DECODE_FAILED", "COSE_Sign1 must be a 4-element array")

    protected, unprotected, payload, signature = value
    if not isinstance(protected, (bytes, bytearray)):
        fail(1, "COSE", "COSE_DECODE_FAILED", "protected header is not bstr")
    if not isinstance(unprotected, dict):
        fail(1, "COSE", "COSE_DECODE_FAILED", "unprotected header is not a map")
    if not isinstance(payload, (bytes, bytearray)) or len(payload) == 0:
        fail(1, "PAYLOAD", "MISSING_PAYLOAD", "payload missing or empty")
    if not isinstance(signature, (bytes, bytearray)):
        fail(2, "SIG", "BAD_SIG_LENGTH", "signature is not bstr")

    return bytes(protected), unprotected, bytes(payload), bytes(signature)


def decode_protected_header(protected_bstr: bytes) -> dict[Any, Any]:
    if protected_bstr == b"":
        return {}
    try:
        hdr = cbor2.loads(protected_bstr)
    except Exception as exc:
        fail(1, "COSE", "COSE_DECODE_FAILED", f"protected header decode failed: {exc}")
    if not isinstance(hdr, dict):
        fail(1, "COSE", "COSE_DECODE_FAILED", "protected header is not a map")
    return hdr


def verify_sig_structure(protected_bstr: bytes, payload: bytes, signature: bytes, public_key: bytes) -> None:
    if len(signature) != 64:
        fail(2, "SIG", "BAD_SIG_LENGTH", f"expected 64-byte Ed25519 signature, got {len(signature)}")
    if len(public_key) != 32:
        fail(2, "SIG", "SIG_FAILED", f"expected 32-byte Ed25519 public key, got {len(public_key)}")

    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload])
    try:
        VerifyKey(public_key).verify(sig_structure, signature)
    except BadSignatureError:
        fail(2, "SIG", "SIG_FAILED", "Ed25519 verification failed")
    except Exception as exc:
        fail(2, "SIG", "SIG_FAILED", f"Ed25519 verification error: {exc}")


def ensure_type(claims: dict[Any, Any], key: int, expected: type, name: str) -> Any:
    if key not in claims:
        fail(3, name, f"MISSING_CLAIM:{name}", f"missing claim key {key}")
    value = claims[key]
    if not isinstance(value, expected):
        fail(3, name, f"WRONG_TYPE:{name}", f"claim {name} has wrong type: {type(value).__name__}")
    return value


def ensure_bstr_len(value: Any, expected_len: int, layer: int, check: str, code: str, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        fail(layer, check, code, f"{name} is not bytes")
    b = bytes(value)
    if len(b) != expected_len:
        fail(layer, check, code, f"{name} length {len(b)} != {expected_len}")
    return b


def decode_and_validate_claims(payload: bytes) -> dict[Any, Any]:
    try:
        claims = cbor2.loads(payload)
    except Exception as exc:
        fail(1, "CLAIMS_DECODE", "PAYLOAD_NOT_MAP", f"claims decode failed: {exc}")
    if not isinstance(claims, dict):
        fail(1, "CLAIMS_DECODE", "PAYLOAD_NOT_MAP", "payload is not a CBOR map")

    # Layer 1-ish (parse/profile): eat_profile
    profile = ensure_type(claims, EAT_PROFILE, str, "EAT_PROFILE")
    if profile != AIR_PROFILE_URI:
        fail(1, "EAT_PROFILE", "WRONG_PROFILE", f"wrong eat_profile: {profile}")

    # Basic required standard claim types
    _ = ensure_type(claims, CWT_ISS, str, "ISS")
    iat = ensure_type(claims, CWT_IAT, int, "IAT")
    if iat < 0:
        fail(3, "IAT", "WRONG_TYPE:IAT", "iat must be unsigned")
    cti = ensure_type(claims, CWT_CTI, (bytes, bytearray), "CTI")
    cti_b = ensure_bstr_len(cti, 16, 3, "CTI", "BAD_CTI_LENGTH", "cti")
    if cti_b == b"\x00" * 16:
        fail(3, "CTI", "BAD_CTI_LENGTH", "cti is all zeros")

    # Optional nonce type
    if EAT_NONCE in claims and not isinstance(claims[EAT_NONCE], (bytes, bytearray)):
        fail(3, "NONCE", "WRONG_TYPE:NONCE", "eat_nonce must be bytes")

    # Required AIR claims
    _ = ensure_type(claims, AIR_MODEL_ID, str, "MODEL_ID")
    _ = ensure_type(claims, AIR_MODEL_VERSION, str, "MODEL_VERSION")
    model_hash = ensure_type(claims, AIR_MODEL_HASH, (bytes, bytearray), "MHASH_PRESENT")
    model_hash_b = ensure_bstr_len(model_hash, 32, 3, "MHASH_PRESENT", "BAD_HASH_LENGTH:model_hash", "model_hash")
    if model_hash_b == b"\x00" * 32:
        fail(3, "MHASH_PRESENT", "ZERO_MODEL_HASH", "model_hash is all zeros")

    ensure_bstr_len(
        ensure_type(claims, AIR_REQUEST_HASH, (bytes, bytearray), "REQUEST_HASH"),
        32,
        3,
        "REQUEST_HASH",
        "BAD_HASH_LENGTH:request_hash",
        "request_hash",
    )
    ensure_bstr_len(
        ensure_type(claims, AIR_RESPONSE_HASH, (bytes, bytearray), "RESPONSE_HASH"),
        32,
        3,
        "RESPONSE_HASH",
        "BAD_HASH_LENGTH:response_hash",
        "response_hash",
    )
    ensure_bstr_len(
        ensure_type(claims, AIR_ATTESTATION_DOC_HASH, (bytes, bytearray), "ATTESTATION_DOC_HASH"),
        32,
        3,
        "ATTESTATION_DOC_HASH",
        "BAD_HASH_LENGTH:attestation_doc_hash",
        "attestation_doc_hash",
    )

    _ = ensure_type(claims, AIR_POLICY_VERSION, str, "POLICY_VERSION")
    _ = ensure_type(claims, AIR_SECURITY_MODE, str, "SECURITY_MODE")
    for key, check in [
        (AIR_SEQUENCE_NUMBER, "SEQ"),
        (AIR_EXECUTION_TIME_MS, "EXEC_MS"),
        (AIR_MEMORY_PEAK_MB, "MEM_MB"),
    ]:
        value = ensure_type(claims, key, int, check)
        if value < 0:
            fail(3, check, f"WRONG_TYPE:{check}", f"{check} must be unsigned")

    # Measurements
    measurements = ensure_type(claims, AIR_ENCLAVE_MEASUREMENTS, dict, "MEAS")
    mtype = measurements.get("measurement_type")
    if not isinstance(mtype, str):
        fail(3, "MTYPE", "UNKNOWN_MTYPE:<non-string>", "measurement_type missing or not a string")
    if mtype not in ALLOWED_MEASUREMENT_TYPES:
        fail(3, "MTYPE", f"UNKNOWN_MTYPE:{mtype}", f"unknown measurement_type: {mtype}")
    for pcr in ("pcr0", "pcr1", "pcr2"):
        if pcr not in measurements:
            fail(3, "MEAS", "BAD_MEASUREMENT_LENGTH", f"missing {pcr}")
        ensure_bstr_len(measurements[pcr], 48, 3, "MEAS", "BAD_MEASUREMENT_LENGTH", pcr)
    if "pcr8" in measurements and measurements["pcr8"] is not None:
        ensure_bstr_len(measurements["pcr8"], 48, 3, "MEAS", "BAD_MEASUREMENT_LENGTH", "pcr8")

    # Optional model_hash_scheme (fail-closed if unknown)
    if AIR_MODEL_HASH_SCHEME in claims:
        scheme = claims[AIR_MODEL_HASH_SCHEME]
        if not isinstance(scheme, str):
            fail(3, "MHASH_SCHEME", "WRONG_TYPE:MHASH_SCHEME", "model_hash_scheme must be a string")
        if scheme not in ALLOWED_MODEL_HASH_SCHEMES:
            fail(3, "MHASH_SCHEME", f"UNKNOWN_MODEL_HASH_SCHEME:{scheme}", f"unknown model_hash_scheme: {scheme}")

    return claims


def apply_policy(claims: dict[Any, Any], policy: VerifyPolicy, now_epoch: int) -> None:
    iat = int(claims[CWT_IAT])
    if policy.max_age_secs > 0:
        if iat > now_epoch + policy.clock_skew_secs:
            fail(4, "FRESH", "TIMESTAMP_FUTURE", "iat is in the future")
        age = max(0, now_epoch - iat)
        if age > policy.max_age_secs:
            fail(4, "FRESH", "TIMESTAMP_STALE", f"receipt age {age}s exceeds max {policy.max_age_secs}s")

    if policy.expected_model_hash is not None:
        actual = bytes(claims[AIR_MODEL_HASH])
        if actual != policy.expected_model_hash:
            fail(4, "MHASH", "MODEL_HASH_MISMATCH", "model_hash does not match policy")

    if policy.expected_model_id is not None:
        actual_id = claims[AIR_MODEL_ID]
        if actual_id != policy.expected_model_id:
            fail(4, "MODEL", "MODEL_ID_MISMATCH", "model_id does not match policy")

    if policy.expected_platform is not None and policy.expected_platform != "any":
        measurements = claims[AIR_ENCLAVE_MEASUREMENTS]
        actual_platform = measurements.get("measurement_type")
        if actual_platform != policy.expected_platform:
            fail(4, "PLATFORM", "PLATFORM_MISMATCH", "measurement_type does not match policy")

    has_nonce = EAT_NONCE in claims
    if policy.require_nonce and not has_nonce:
        fail(4, "NONCE", "NONCE_MISSING", "eat_nonce required but absent")
    if policy.expected_nonce is not None:
        if not has_nonce:
            fail(4, "NONCE", "NONCE_MISSING", "eat_nonce missing")
        actual_nonce = bytes(claims[EAT_NONCE])
        if actual_nonce != policy.expected_nonce:
            fail(4, "NONCE", "NONCE_MISMATCH", "eat_nonce does not match policy")


def build_policy(policy_obj: dict[str, Any] | None) -> VerifyPolicy:
    if not policy_obj:
        return VerifyPolicy()
    policy = VerifyPolicy()
    if "expected_nonce_hex" in policy_obj:
        policy.expected_nonce = hex_to_bytes(policy_obj["expected_nonce_hex"], "expected_nonce_hex")
    if "expected_model_hash_hex" in policy_obj:
        policy.expected_model_hash = hex_to_bytes(policy_obj["expected_model_hash_hex"], "expected_model_hash_hex")
    if "expected_platform" in policy_obj:
        policy.expected_platform = str(policy_obj["expected_platform"])
    if "expected_model_id" in policy_obj:
        policy.expected_model_id = str(policy_obj["expected_model_id"])
    if "max_age_secs" in policy_obj:
        policy.max_age_secs = int(policy_obj["max_age_secs"])
    if "clock_skew_secs" in policy_obj:
        policy.clock_skew_secs = int(policy_obj["clock_skew_secs"])
    if "require_nonce" in policy_obj:
        policy.require_nonce = bool(policy_obj["require_nonce"])
    return policy


def verify_vector(vec: dict[str, Any], now_epoch: int) -> VerificationResult:
    try:
        receipt_bytes = hex_to_bytes(vec["receipt_hex"], "receipt_hex")
        pubkey_field = "public_key_hex" if "public_key_hex" in vec else "wrong_public_key_hex"
        if pubkey_field not in vec:
            raise KeyError("public_key_hex")
        public_key = hex_to_bytes(vec[pubkey_field], pubkey_field)
        policy = build_policy(vec.get("verify_policy"))

        protected_bstr, _uhdr, payload, signature = parse_receipt_cose(receipt_bytes)
        protected = decode_protected_header(protected_bstr)

        alg = protected.get(COSE_ALG_KEY)
        if alg != COSE_ALG_EDDSA:
            fail(1, "ALG", "BAD_ALG", f"alg {alg!r} != -8")

        content_type = protected.get(COSE_CONTENT_TYPE_KEY)
        if content_type != COSE_CONTENT_TYPE_CWT:
            fail(1, "CONTENT_TYPE", "BAD_CONTENT_TYPE", f"content_type {content_type!r} != 61")

        if "payload_hex" in vec:
            expected_payload = hex_to_bytes(vec["payload_hex"], "payload_hex")
            if payload != expected_payload:
                fail(1, "PAYLOAD", "PAYLOAD_NOT_MAP", "payload bytes do not match payload_hex fixture")

        claims = decode_and_validate_claims(payload)
        verify_sig_structure(protected_bstr, payload, signature, public_key)
        apply_policy(claims, policy, now_epoch)
        return VerificationResult(ok=True)
    except AirVerifyError as exc:
        return VerificationResult(ok=False, failure=exc.failure)


def iter_vector_files(vectors_dir: Path, selected_name: str | None) -> list[Path]:
    files = sorted((vectors_dir / "valid").glob("*.json")) + sorted((vectors_dir / "invalid").glob("*.json"))
    if selected_name is None:
        return files
    filtered = [p for p in files if p.stem == selected_name or p.name == selected_name]
    if not filtered:
        raise FileNotFoundError(f"vector not found: {selected_name}")
    return filtered


def evaluate_vector(path: Path, now_epoch: int, verbose: bool) -> bool:
    vec = load_json(path)
    result = verify_vector(vec, now_epoch)
    name = vec.get("name", path.stem)

    if "expected_failure" in vec:
        expected = vec["expected_failure"]
        if result.ok:
            print(f"FAIL {name}: expected failure {expected['code']}, got PASS")
            return False
        actual = result.failure
        assert actual is not None
        ok = (
            actual.code == expected.get("code")
            and actual.check == expected.get("check")
            and actual.layer == int(expected.get("layer"))
        )
        if ok:
            print(f"PASS {name}: expected failure {actual.code} (L{actual.layer}/{actual.check})")
            if verbose:
                print(f"  reason: {actual.reason}")
            return True
        print(
            f"FAIL {name}: expected {expected.get('code')} (L{expected.get('layer')}/{expected.get('check')}), "
            f"got {actual.code} (L{actual.layer}/{actual.check})"
        )
        if verbose:
            print(f"  reason: {actual.reason}")
        return False

    # Valid vector
    if result.ok:
        print(f"PASS {name}: valid vector accepted")
        return True
    assert result.failure is not None
    print(
        f"FAIL {name}: expected PASS, got {result.failure.code} "
        f"(L{result.failure.layer}/{result.failure.check})"
    )
    if verbose:
        print(f"  reason: {result.failure.reason}")
    return False


def main(argv: list[str]) -> int:
    script_dir = Path(__file__).resolve().parent
    default_vectors = (script_dir.parent / "vectors").resolve()

    parser = argparse.ArgumentParser(description="Run AIR v1 vector interoperability checks")
    parser.add_argument("--vectors-dir", type=Path, default=default_vectors, help="Path to spec/v1/vectors")
    parser.add_argument("--vector", help="Run a single vector by filename or stem")
    parser.add_argument("--now-epoch", type=int, default=int(time.time()), help="Unix time for freshness checks")
    parser.add_argument("--verbose", action="store_true", help="Print failure reasons")
    args = parser.parse_args(argv)

    try:
        files = iter_vector_files(args.vectors_dir, args.vector)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not files:
        print(f"No vector files found under {args.vectors_dir}", file=sys.stderr)
        return 2

    print(f"AIR v1 interop test: {len(files)} vector(s) from {args.vectors_dir}")
    print(f"now_epoch={args.now_epoch}")

    passed = 0
    for path in files:
        if evaluate_vector(path, args.now_epoch, args.verbose):
            passed += 1

    total = len(files)
    failed = total - passed
    print(f"\nSummary: {passed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
