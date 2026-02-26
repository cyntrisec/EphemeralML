# M4 — Interop & Design Partner Readiness

**Goal:** One external verifier (or second internal implementation in a different language) successfully verifies AIR v1 receipts against all 10 golden vectors.

**Baseline:** M3 frozen (`m3-spec-frozen` tag), CI green, all audit findings fixed (`284fbc9`).

---

## Phase 1: External Interop Test (Days 1-3)

### 1.1 Publish interop test script
- [x] Create `spec/v1/scripts/interop_test.py` — standalone Python script that verifies all 10 vectors
- [x] Zero dependencies beyond `pip install cbor2 pycose PyNaCl` (common, well-maintained)
- [x] Script must: load each vector JSON, decode receipt_hex, verify signature, validate claims, check expected pass/fail
- [x] Script exits 0 on full pass, non-zero with diagnostics on any failure
- [x] Test script locally against vectors before publishing

### 1.2 Validate interop script on clean machine
- [ ] Run on a fresh Python 3.10+ virtualenv with no project code installed
- [ ] Confirm it works on macOS and Linux
- [ ] All 10 vectors: 2 valid PASS, 4 structural FAIL (correct code), 4 policy FAIL (correct code)

### 1.3 Create interop test runner (Go, optional stretch)
- [ ] If time permits: `spec/v1/scripts/interop_test.go` using `go-cose` + `crypto/ed25519`
- [ ] Same 10-vector coverage, same exit behavior
- [ ] Validates that the spec is language-agnostic, not just Python-friendly

## Phase 2: Spec Publication (Days 2-4)

### 2.1 Create public spec package
- [ ] Tag `air-v1.0-frozen` on the commit that includes interop script
- [ ] GitHub Release with:
  - Spec docs (CDDL, claim-mapping, interop-kit, RELEASE.md)
  - Golden vectors (all 10 JSON files)
  - Interop test script(s)
  - Limitations doc
- [ ] Release description links to interop-kit.md as entry point

### 2.2 Update README
- [x] Add "AIR v1 Spec" section to top-level EphemeralML README
- [x] Link to `spec/v1/interop-kit.md` and `spec/v1/RELEASE.md`
- [ ] Badge: `AIR v1.0 FROZEN` shield

### 2.3 Update crates.io metadata (if publishing common crate)
- [ ] Consider publishing `ephemeral-ml-common` as a standalone crate with AIR v1 build/parse/verify
- [ ] Or keep it workspace-internal — decide based on partner needs

## Phase 3: Implementation Status Note (Days 3-5)

### 3.1 Create implementation-status.md
- [x] Document what is implemented vs backlog in the Rust reference verifier
- [x] Explicitly list:
  - All 9 mandatory checks: PARSE, ALG, CONTENT_TYPE, SIG, PROFILE, CTI, MHASH, MEAS, MTYPE — all implemented
  - All 4 optional policy checks: FRESH, MODEL, PLATFORM, NONCE — all implemented
  - model_hash_scheme validation: implemented (fail-closed on unknown)
  - TDX DCAP chain: T3_CHAIN partially verified (collateral binding done, QE identity/TCB/FMSPC gaps remain)
  - CS JWT: runtime enforcement done (audience, MRTD, issuer, expiry, nonce, signature)
  - Replay detection (CTI dedup): verifier supports `seen_cti` callback hook; caller must supply stateful cache
  - Pipeline chaining: not in v1 scope
- [x] Link from interop-kit.md §8 "Known Implementations"

### 3.2 Update interop-kit.md
- [x] Change §8 table to include test count, last-verified date, and link to implementation-status.md
- [x] Add Python interop script to §8 table once validated

## Phase 4: Design Partner Outreach Prep (Days 4-7)

### 4.1 Create one-page brief
- [ ] Title: "AIR v1 — Cryptographic Receipts for Confidential AI Inference"
- [ ] Target audience: compliance officer or CISO at a healthcare/fintech org
- [ ] Contents:
  - Problem (1 paragraph): can't use cloud AI, no auditable evidence
  - Solution (1 paragraph): receipt = proof of what happened inside the TEE
  - What the receipt contains (bullet list of claims)
  - How to verify (3-line summary + link to interop-kit)
  - What platforms it runs on (AWS Nitro, GCP TDX, GCP H100 CC)
  - What it doesn't do yet (limitations — honest)
- [ ] PDF or clean markdown, no slides

### 4.2 Identify first 3 external contacts
- [ ] CCC (Confidential Computing Consortium) — post to projects mailing list
- [ ] rats@ietf.org — intro email (see M5 prep below)
- [ ] 1 specific healthcare/fintech org blocked from cloud AI

### 4.3 Run interop with first external user
- [ ] Provide: interop-kit.md + vectors + interop_test.py + one-page brief
- [ ] Ask them to: run script, report any issues, attempt their own implementation
- [ ] Success criteria: they can verify at least the 2 valid vectors independently
- [ ] Collect feedback on spec clarity, claim naming, missing checks

## Phase 5: M5 Prep — IETF Draft Skeleton (Parallel, Low Priority)

### 5.1 Draft AIR I-D skeleton
- [ ] Use `xml2rfc` or `kramdown-rfc` tooling
- [ ] Title: "Attested Inference Receipt (AIR) — A COSE/CWT Profile for Confidential AI Inference"
- [ ] Target WG: RATS (Remote Attestation Procedures)
- [ ] Sections: Introduction, Terminology, Receipt Format (CDDL), Claim Semantics, Verification Procedure, Security Considerations, IANA Considerations
- [ ] DO NOT submit until interop proof exists

### 5.2 Draft rats@ietf.org intro email
- [ ] Introduce problem space
- [ ] Link to spec + vectors + interop results
- [ ] Ask: is this in scope for RATS? Would it fit as a RATS document or a standalone draft?
- [ ] Mention EAT profile usage (RFC 9711)
- [ ] DO NOT send until at least 1 external interop pass

---

## M4 Exit Criteria

| Criterion | Required |
|-----------|----------|
| Python interop script passes all 10 vectors | Yes |
| At least 1 external party verifies 2+ valid vectors | Yes |
| implementation-status.md published | Yes |
| GitHub Release with spec + vectors + scripts | Yes |
| EphemeralML README links to spec | Yes |
| Go interop script | Stretch |
| IETF draft skeleton exists | Stretch |
| Design partner feedback collected | Stretch |

## What NOT to Do in M4

- Do not broaden AIR v1 claim set
- Do not start pipeline chaining (vNEXT)
- Do not rewrite the verifier unless an interop issue forces it
- Do not add new measurement_type variants without external demand
- Do not submit IETF draft before interop proof
