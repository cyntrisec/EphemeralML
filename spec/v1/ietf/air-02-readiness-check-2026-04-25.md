# AIR -02 Readiness Check

Date: 2026-04-25

Scope: `draft-tsyrulnikov-rats-attested-inference-receipt-02` submission artifacts in `spec/v1/ietf/`.

## Result

AIR `-02` is technically ready for Datatracker upload from the committed XML artifact:

```text
spec/v1/ietf/draft-tsyrulnikov-rats-attested-inference-receipt-02.xml
```

Strategic decision remains separate: submit immediately, or hold until the A-197 / BYOC evidence gate if that evidence materially improves external credibility.

## Checks Run

```bash
env HOME=/tmp idnits spec/v1/ietf/draft-tsyrulnikov-rats-attested-inference-receipt-02.txt
```

Result: `0 errors`, `0 flaws`, `0 warnings`.

`idnits` emitted nine informational comments for manually declared Internet-Draft references. These are not submission blockers; the draft uses explicit reference metadata for current RATS / SCITT drafts that local `idnits` did not resolve.

```bash
tmp=$(mktemp -d)
cache=/tmp/xml2rfc-cache
mkdir -p "$cache"
cp spec/v1/ietf/draft-tsyrulnikov-rats-attested-inference-receipt-02.xml "$tmp/"
cd "$tmp"
xml2rfc --cache="$cache" --text --html draft-tsyrulnikov-rats-attested-inference-receipt-02.xml
```

Result: text and HTML render successfully from the committed XML.

Non-blocking output:

- `xml2rfc` reported one artwork-width warning and reduced indentation automatically.

## CI Status

The `IETF Draft` workflow succeeded on commit `917eba0`. Main repository CI, Pages, and CodeQL succeeded on the implementation baseline commit `0e2d934` before this documentation-only readiness note was added.

## Submission Artifact

Upload this file to Datatracker when ready:

```text
spec/v1/ietf/draft-tsyrulnikov-rats-attested-inference-receipt-02.xml
```

Do not upload the Markdown source. The Markdown source remains the editable `kramdown-rfc` input.
