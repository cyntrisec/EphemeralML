#!/usr/bin/env python3
"""Generate AIR v1 F-1 signature-strictness conformance vectors.

These four vectors exercise the strict Ed25519 verification algorithm of
the AIR v1 specification (Verification Procedure, Layer 2). Each is a full
COSE_Sign1 AIR receipt that a conformant verifier MUST reject:

  v1-sig-s-out-of-range  -- check (a): scalar S is congruent modulo L but
                            lies outside [0, L); S MUST NOT be reduced.
  v1-sig-small-order-r   -- check (c): the signature point R has small order.
  v1-sig-small-order-a   -- check (c): the public key A has small order.
  v1-sig-cofactored-only -- check (d): the signature satisfies the cofactored
                            group equation but not the cofactorless one; a
                            verifier using the cofactored equation would
                            wrongly accept it.

Each vector reuses the protected header and payload of the valid golden
vector valid/v1-nitro-no-nonce.json; only the trailing 64-byte signature
differs. Output is fully deterministic -- fixed key seed, fixed base
receipt, fixed SHA-512-derived nonces -- so re-running reproduces
byte-identical files.

Edge-case construction methodology: "Taming the many EdDSA" (Chalkias,
Garillot, Nikolaenko, 2020) and the ed25519-speccheck test suite. The
Ed25519 group arithmetic in the GROUP ARITHMETIC section below is the
public-domain reference code from RFC 8032 Section 6, lightly re-commented;
RFC 8032 names the base-point order `q`, renamed `L` here to match the spec.

Usage:  python3 spec/v1/scripts/gen_f1_vectors.py
Deps:   cbor2  (pip install cbor2)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import cbor2

# ── GROUP ARITHMETIC: RFC 8032 Section 6 reference code (public domain) ──


def sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


p = 2**255 - 19  # field prime


def modp_inv(x: int) -> int:
    return pow(x, p - 2, p)


d = -121665 * modp_inv(121666) % p  # Edwards curve constant
L = 2**252 + 27742317777372353535851937790883648493  # base-point order (RFC 8032 `q`)


def sha512_modL(s: bytes) -> int:
    return int.from_bytes(sha512(s), "little") % L


# Points are (X, Y, Z, T) extended coordinates: x = X/Z, y = Y/Z, x*y = T/Z.
NEUTRAL = (0, 1, 1, 0)


def point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B_ = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B_ - A, D - C, D + C, B_ + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def point_mul(s: int, P):
    Q = NEUTRAL
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q


def point_equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True


modp_sqrt_m1 = pow(2, (p - 1) // 4, p)


def recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * modp_inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
B = (g_x, g_y, 1, g_x * g_y % p)  # Ed25519 base point


def point_compress(P) -> bytes:
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(s: bytes):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


# ── END RFC 8032 reference code ─────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
VECTORS_DIR = SCRIPT_DIR.parent / "vectors"
GOLDEN = json.loads((VECTORS_DIR / "valid" / "v1-nitro-no-nonce.json").read_text())

# Ed25519 secret scalar `a` from the AIR golden-vector key seed
# (RFC 8032 Section 5.1.5 key expansion: SHA-512 of the seed, then clamp).
SEED = bytes([0x2A] * 32)
_h = bytearray(sha512(SEED)[:32])
_h[0] &= 248
_h[31] &= 127
_h[31] |= 64
a = int.from_bytes(_h, "little")
A_pt = point_mul(a, B)
A_bytes = point_compress(A_pt)
# Correctness gate: this derivation must reproduce the published golden
# public key. If it does, the group arithmetic above is sound.
assert A_bytes.hex() == GOLDEN["public_key_hex"], (
    f"derived public key {A_bytes.hex()} != golden {GOLDEN['public_key_hex']}"
)

# The unique point of order 2 on edwards25519: (x, y) = (0, -1).
# -x^2 + y^2 = 1 + d*x^2*y^2  =>  with x = 0: 1 = 1.  [2](0,-1) = neutral.
P2 = (0, p - 1, 1, 0)
assert point_equal(point_mul(2, P2), NEUTRAL), "P2 is not order 2"
assert not point_equal(P2, NEUTRAL), "P2 must not be the neutral element"
P2_bytes = point_compress(P2)

# Base receipt -> COSE Sig_structure1 (the message M the signature covers).
receipt = bytes.fromhex(GOLDEN["receipt_hex"])
_tag = cbor2.loads(receipt)
assert getattr(_tag, "tag", None) == 18, "golden receipt is not COSE_Sign1 tag 18"
protected_bstr, _unprotected, payload_bstr, golden_sig = _tag.value
assert len(golden_sig) == 64
M = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
# The signature is the final 64 bytes of the serialized receipt. Splicing a
# replacement signature in place leaves every other byte -- framing, headers,
# payload -- identical to the golden vector the verifiers already accept.
assert receipt[-64:] == golden_sig
RECEIPT_PREFIX = receipt[:-64]


def encode_scalar(s: int) -> bytes:
    return s.to_bytes(32, "little")


# ── (a) non-canonical scalar S ──────────────────────────────────────────
# Replace S with S + L: congruent modulo L (so both group equations still
# hold) but outside [0, L). Layer 2 check (a) MUST reject it.
R_a = golden_sig[:32]
S_a = int.from_bytes(golden_sig[32:], "little")
assert S_a < L, "golden signature S is already non-canonical"
# Self-check: confirm the golden signature verifies (cofactorless). This
# also validates M and the group arithmetic against a known-good signature.
k_g = sha512_modL(R_a + A_bytes + M)
assert point_equal(point_mul(S_a, B), point_add(point_decompress(R_a), point_mul(k_g, A_pt)))
S_a_bad = S_a + L
assert S_a_bad >= L and S_a_bad < 2**256
sig_a = R_a + encode_scalar(S_a_bad)

# ── (c-R) small-order R ─────────────────────────────────────────────────
# R is the order-2 point. With S = k*a the cofactored equation holds, but
# the cofactorless equation cannot (its right side carries the torsion R).
k_b = sha512_modL(P2_bytes + A_bytes + M)
S_b = (k_b * a) % L
_lhs = point_mul(S_b, B)
assert not point_equal(_lhs, point_add(P2, point_mul(k_b, A_pt))), "c-R cofactorless holds"
assert point_equal(
    point_mul(8, _lhs), point_add(point_mul(8, P2), point_mul(8, point_mul(k_b, A_pt)))
), "c-R cofactored equation fails"
sig_b = P2_bytes + encode_scalar(S_b)

# ── (c-A) small-order public key A ──────────────────────────────────────
# The verifying key is the order-2 point. A normal-looking (R, S=r) makes
# the cofactored equation hold; the small-order-A check MUST still reject.
_n = 0
while True:
    r_c = sha512_modL(b"AIR-F1/small-order-a/" + _n.to_bytes(4, "little") + M)
    R_c_pt = point_mul(r_c, B)
    R_c = point_compress(R_c_pt)
    k_c = sha512_modL(R_c + P2_bytes + M)
    # Require k_c odd, so [k_c]P2 = P2 != neutral and the cofactorless
    # equation also fails unambiguously (check (c) rejects it regardless).
    if k_c % 2 == 1:
        break
    _n += 1
S_c = r_c % L
assert point_equal(point_mul(S_c, B), R_c_pt)
assert not point_equal(point_mul(S_c, B), point_add(R_c_pt, point_mul(k_c, P2))), "c-A cofactorless holds"
assert point_equal(
    point_mul(8, point_mul(S_c, B)),
    point_add(point_mul(8, R_c_pt), point_mul(8, point_mul(k_c, P2))),
), "c-A cofactored equation fails"
sig_c = R_c + encode_scalar(S_c)

# ── (d) cofactored-valid but cofactorless-invalid ───────────────────────
# R' = [r]B + P2 adds an order-2 torsion component. With S = r + k*a the
# cofactored equation holds (the torsion vanishes under [8]); the
# cofactorless equation fails. R' is not small-order, so only check (d)
# catches it -- this isolates "verifier used the cofactored equation".
r_d = sha512_modL(b"AIR-F1/cofactored-only/" + M)
R_prime = point_add(point_mul(r_d, B), P2)
R_d = point_compress(R_prime)
assert not point_equal(point_mul(8, R_prime), NEUTRAL), "R' is small-order"
k_d = sha512_modL(R_d + A_bytes + M)
S_d = (r_d + k_d * a) % L
assert not point_equal(point_mul(S_d, B), point_add(R_prime, point_mul(k_d, A_pt))), "d cofactorless holds"
assert point_equal(
    point_mul(8, point_mul(S_d, B)),
    point_add(point_mul(8, R_prime), point_mul(8, point_mul(k_d, A_pt))),
), "d cofactored equation fails"
sig_d = R_d + encode_scalar(S_d)

# ── Emit vector files ───────────────────────────────────────────────────

VECTORS = [
    {
        "name": "v1-sig-s-out-of-range",
        "sig": sig_a,
        "public_key": A_bytes,
        "description": (
            "AIR v1 receipt whose Ed25519 signature scalar S has been replaced "
            "with S + L (L = Ed25519 group order). S + L is congruent to a valid "
            "S modulo L but is not in [0, L). Verification Procedure Layer 2 check "
            "(a) MUST reject it; a verifier that reduces S modulo L would wrongly "
            "accept it. Edge case: non-canonical S (Taming the many EdDSA / "
            "ed25519-speccheck)."
        ),
        "reason": "signature scalar S is not in [0, L) (S + L substituted for S)",
    },
    {
        "name": "v1-sig-small-order-r",
        "sig": sig_b,
        "public_key": A_bytes,
        "description": (
            "AIR v1 receipt whose signature point R is the edwards25519 point of "
            "order 2. The signature satisfies the cofactored group equation but "
            "not the cofactorless one. Verification Procedure Layer 2 check (c) "
            "MUST reject a small-order R. Edge case: small-order R (Taming the "
            "many EdDSA / ed25519-speccheck)."
        ),
        "reason": "signature point R is a small-order point",
    },
    {
        "name": "v1-sig-small-order-a",
        "sig": sig_c,
        "public_key": P2_bytes,
        "description": (
            "AIR v1 receipt verified against a public key A that is the "
            "edwards25519 point of order 2. The signature makes the cofactored "
            "group equation hold. Verification Procedure Layer 2 check (c) MUST "
            "reject a small-order A. Edge case: small-order A (Taming the many "
            "EdDSA / ed25519-speccheck)."
        ),
        "reason": "public key A is a small-order point",
    },
    {
        "name": "v1-sig-cofactored-only",
        "sig": sig_d,
        "public_key": A_bytes,
        "description": (
            "AIR v1 receipt whose signature satisfies the cofactored group "
            "equation [8][S]B = [8]R + [8][k]A but not the cofactorless equation "
            "[S]B = R + [k]A: R carries an order-2 torsion component. R is not "
            "itself small-order, so only Verification Procedure Layer 2 check (d) "
            "catches it -- a verifier that uses the cofactored equation would "
            "wrongly accept it. Edge case: cofactored vs cofactorless (Taming the "
            "many EdDSA / ed25519-speccheck)."
        ),
        "reason": "signature satisfies the cofactored but not the cofactorless equation",
    },
]

for v in VECTORS:
    new_receipt = RECEIPT_PREFIX + v["sig"]
    assert len(v["sig"]) == 64
    obj = {
        "name": v["name"],
        "description": v["description"],
        "receipt_hex": new_receipt.hex(),
        "public_key_hex": v["public_key"].hex(),
        "expected_failure": {
            "layer": 2,
            "check": "SIG",
            "code": "SIG_FAILED",
            "reason": v["reason"],
        },
        "version": "1.0",
        "date": "2026-05-22",
    }
    out_path = VECTORS_DIR / "invalid" / f"{v['name']}.json"
    out_path.write_text(json.dumps(obj, indent=2) + "\n")
    print(f"wrote invalid/{v['name']}.json  (receipt {len(new_receipt)} bytes)")

print("F-1 signature-strictness vectors generated; all self-checks passed.")
