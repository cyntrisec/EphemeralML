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
| `air-02-readiness-check-2026-04-25.md` | Final local readiness check before possible `-02` Datatracker upload |
| `rats-intro-email-draft.md` | Draft email for `rats@ietf.org` to request feedback on scope and charter fit |

## Build Pipeline

The `IETF Draft` GitHub Actions workflow rebuilds the `-02` source with
`kramdown-rfc`, renders text and HTML with `xml2rfc`, and verifies that
the draft is renderable. The workflow intentionally does not byte-compare
generated XML/text/HTML artifacts because `xml2rfc`, Ruby, and Python
generator metadata can churn across hosted runner images without changing
the draft content.

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
- AIR `-02` **was submitted** on 2026-07-05 and is posted on
  [Datatracker](https://datatracker.ietf.org/doc/draft-tsyrulnikov-rats-attested-inference-receipt/).
- The committed Markdown source and XML/text artifacts mirror the published
  `-02` submission. HTML rendering can vary with the `xml2rfc` version.
- The pre-submission readiness check is retained for history; see
  `air-02-readiness-check-2026-04-25.md`.

Revision policy:

1. Preserve the posted `-02` source and generated artifacts as a reproducible
   publication snapshot.
2. Put subsequent semantic changes in a new Internet-Draft revision rather
   than silently rewriting the posted `-02` snapshot.
3. Use `rats-intro-email-draft.md` as historical input for future RATS outreach.
