# Note on the assurance level of this packet

Added 2026-11-19. The files of the packet are unchanged and still match
`SHA256SUMS`; this note is not part of the packet.

`execution-report/verification-report.json` states
`"assurance_level": "tee_provenance"`. It was produced by `ephemeralml-report`
0.2.9 as that program stood on 2026-05-03.

What the report itself records:

- attestation-hash binding (`ADHASH`): pass;
- signing-key binding: pass;
- `NONCE`: skip, `REPLAY`: skip, so no freshness mechanism was bound;
- no check that appraises the measurements against reference values.

At that date the program labelled a report `tee_provenance` on the first two
points alone. Since then the receipt format's draft
(`draft-tsyrulnikov-rats-attested-inference-receipt-02`, Validator Behavior)
requires, before TEE provenance is asserted, that the receipt's measurements
are reconciled against the attestation document and appraised against
reference values, and that the verifier binds a freshness mechanism: its own
nonce, or `cti` deduplication. The program now takes its level from the client
library's chained verifier, which applies those rules, and reports
`tee_provenance` only when it is given reference measurements
(`--expected-pcr0`, `--expected-pcr1`, `--expected-pcr2`) and a verifier nonce
(`--expected-nonce`) that the receipt carries.

Read this packet's label accordingly: it shows that the receipt names the
supplied Nitro attestation document and was signed by the key that document
carries. It does not show that the enclave's measurements were checked against
a known-good build, and it does not rule out that the receipt was presented
more than once.
