# AIR v1 IETF Prep (Non-Normative)

This directory contains non-normative AIR Internet-Draft work for `RATS`, including posted drafts and local preparation for the next Datatracker submission.

These files are:

- **non-normative**
- **not** part of the AIR v1.0 FROZEN specification
- working drafts for community outreach and IETF submission preparation

## Files

| File | Purpose |
|------|---------|
| `air-v1-rats-draft-outline.md` | AIR `-00` Internet-Draft outline aligned to IETF/RATS expectations |
| `draft-tsyrulnikov-rats-attested-inference-receipt-02.md` | Current `kramdown-rfc` source for AIR `-02` |
| `draft-tsyrulnikov-rats-attested-inference-receipt-02.xml` | Generated XML submission artifact |
| `draft-tsyrulnikov-rats-attested-inference-receipt-02.txt` | Generated text rendering |
| `draft-tsyrulnikov-rats-attested-inference-receipt-02.html` | Generated HTML rendering |
| `rats-intro-email-draft.md` | Draft email for `rats@ietf.org` to request feedback on scope and charter fit |

## Build Pipeline

The `IETF Draft` GitHub Actions workflow rebuilds the `-02` source with
`kramdown-rfc`, renders text and HTML with `xml2rfc`, and fails if the
generated XML/text/HTML artifacts are not committed.

Local equivalent:

```bash
cd spec/v1/ietf
kramdown-rfc draft-tsyrulnikov-rats-attested-inference-receipt-02.md > draft-tsyrulnikov-rats-attested-inference-receipt-02.xml
xml2rfc --text draft-tsyrulnikov-rats-attested-inference-receipt-02.xml
xml2rfc --html draft-tsyrulnikov-rats-attested-inference-receipt-02.xml
```

## Submission Status

- AIR `-00` **was submitted** and is posted on Datatracker as `draft-tsyrulnikov-rats-attested-inference-receipt-00`.
- AIR `-01` **was submitted** after `-00`.
- AIR `-02` is currently local prep in this directory (`draft-tsyrulnikov-rats-attested-inference-receipt-02.*`).
- `rats@ietf.org` intro email / announcement has **not** been sent yet.

Planned sequencing:

1. Public implementation status + interop results
2. AIR `-02` architectural cleanup (trust model, closed scope, consistency)
3. RATS mailing list introduction and review request
4. Datatracker submission of `-01`
