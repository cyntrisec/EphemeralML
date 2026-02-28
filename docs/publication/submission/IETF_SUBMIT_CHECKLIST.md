# IETF Internet-Draft Submission Checklist

**Draft:** `draft-tsyrulb-rats-attested-inference-receipt-00`
**Target date:** March 2, 2026
**Submission URL:** https://datatracker.ietf.org/submit/

## Pre-Submission Verification

- [x] kramdown-rfc2629 build: clean (1 expected I-D metadata warning)
- [x] xml2rfc --text: clean (1 artwork width nit, non-blocking)
- [x] xml2rfc --html: clean
- [x] No TODO/TBD/FIXME placeholders
- [x] BCP 14 (RFC 2119/8174) boilerplate present (Section 2)
- [x] IANA Considerations section present (Section 11)
- [x] Security Considerations section present (Section 9)
- [x] Privacy Considerations section present (Section 10)
- [x] All normative/informative references resolve
- [x] Abstract under 20 lines
- [x] RFC 2119 keywords (MUST/SHOULD/MAY) consistently uppercased
- [x] Protected header hex example correct: `A2012703183D` = {1: -8, 3: 61}
- [x] Verification layers match implementation (alg/content_type/eat_profile in L1)
- [x] EAT profile declaration: 15 positions (RFC 9711 Section 6.3)
- [x] CDDL in Section 4.5 matches Appendix A matches canonical `air-v1.cddl`
- [x] Claim count: 16 required + 2 optional = 18 total
- [x] Private key range: -65537 to -65549
- [x] Golden vectors: 10 (2 valid + 8 invalid), layer assignments correct
- [x] Test count: 575 (verified via `cargo test -q`)
- [x] No disallowed wording (C-101..C-103 guardrails)
- [ ] idnits check (run locally before upload: `idnits draft-tsyrulb-rats-attested-inference-receipt-00.txt`)

## Files to Upload

Upload the **XML** file to the IETF datatracker:

| File | Path | Purpose |
|------|------|---------|
| XML (primary) | `spec/v1/ietf/draft-tsyrulb-rats-attested-inference-receipt-00.xml` | Upload to datatracker |
| Markdown source | `spec/v1/ietf/draft-tsyrulb-rats-attested-inference-receipt-00.md` | Keep in repo (not uploaded) |
| Text (reference) | `spec/v1/ietf/draft-tsyrulb-rats-attested-inference-receipt-00.txt` | Verify rendering |
| HTML (reference) | `spec/v1/ietf/draft-tsyrulb-rats-attested-inference-receipt-00.html` | Verify rendering |

## Datatracker Form Fields

| Field | Value |
|-------|-------|
| Document name | `draft-tsyrulb-rats-attested-inference-receipt-00` |
| Submission type | Individual submission |
| Stream | IETF |
| Group | RATS |
| Author name | Borys Tsyrulnikov |
| Author email | contact@cyntrisec.com |

## Post-Submission Steps

1. [ ] Upload XML to https://datatracker.ietf.org/submit/
2. [ ] Confirm email verification (sent to contact@cyntrisec.com)
3. [ ] Verify rendered HTML/text on datatracker matches local builds
4. [ ] Record submission URL and date in `SUBMISSION_LOG_TEMPLATE.md`
5. [ ] Announce on RATS mailing list (rats@ietf.org) with brief intro
6. [ ] Update `startup-plans/STATE.yaml` task A-011 to `done`

## Known Non-Blocking Items

| Item | Severity | Action |
|------|----------|--------|
| Artwork width warning (CDDL example) | Cosmetic | xml2rfc handles gracefully |
| I-D.messous-rats-eat-ai metadata warning | Expected | Custom I-D reference needs explicit YAML |
| idnits not run in CI | LOW | Run locally before upload |
