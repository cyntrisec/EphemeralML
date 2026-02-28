# NIST-2025-0035 Comment Submission Checklist

**Docket:** NIST-2025-0035
**Target date:** March 9, 2026
**Submission URL:** https://www.regulations.gov (search docket NIST-2025-0035)

## Pre-Submission Verification

- [x] Concise memo format (~4 pages)
- [x] Questions answered: 2(a), 3(a), 3(b), 4(a), 4(d)
- [x] All metrics map to publication evidence bundle
- [x] Diagnostic code counts verified: 27 receipt + 38 attestation
- [x] Test count verified: 575 passing, zero failures
- [x] Overhead claims canonical: +3.2% enclave-only, +3-13% range
- [x] Explicit Limits section present (6 rows)
- [x] No speculative overclaim language
- [x] No disallowed wording (C-101..C-103 guardrails)
- [x] Standards references complete (8 RFCs + FIPS 180-4)
- [x] Plain-text export generated

## Files to Submit

| File | Path | Purpose |
|------|------|---------|
| Markdown (canonical) | `docs/publication/nist-2025-0035-comment.md` | Source of truth |
| Plain text | `docs/publication/nist-2025-0035-comment.txt` | For docket paste |

## Regulations.gov Form Fields

| Field | Value |
|-------|-------|
| Docket ID | NIST-2025-0035 |
| Comment type | Public comment |
| Submitter name | Borys Tsyrulnikov |
| Organization | Cyntrisec |
| Email | borys@cyntrisec.com |

## Submission Options

**Option A (preferred):** Upload the markdown file as an attachment and paste the executive summary into the comment text field.

**Option B:** Paste the full plain-text version (`nist-2025-0035-comment.txt`) into the comment text field.

## Post-Submission Steps

1. [ ] Submit comment on regulations.gov
2. [ ] Save confirmation number and screenshot
3. [ ] Record submission date and confirmation in `SUBMISSION_LOG_TEMPLATE.md`
4. [ ] Update `startup-plans/STATE.yaml` task A-013 to `done`

## Content Summary

| Section | Content |
|---------|---------|
| Executive Summary | AIR v1 overview, tri-cloud validation |
| Q 2(a) | Technical controls: receipts, TEE isolation, 4-layer verification, standards |
| Q 3(a) | Threats: model substitution, environment integrity, formal threat model |
| Q 3(b) | Assessment: layered verification, diagnostic codes, compliance baselines |
| Q 4(a) | Constraints: TEE hardware isolation, attestation-gated key release |
| Q 4(d) | Monitoring: receipt streams, replay detection, model/platform drift |
| Explicit Limits | 6 rows: no deletion proof, hash != correctness, no certification, single-inference, GPU limited, attestation out of scope |
| Evidence Summary | 3 platforms, tag reference, test count, spec status |
