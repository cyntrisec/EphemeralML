# Draft Email — `rats@ietf.org` Introduction (Not Sent)

**Status:** Updated 2026-03-07 after archive review-pattern analysis. Draft is scoped for the first architectural intro on `rats@ietf.org`.

## Subject (draft)

`Introducing draft-tsyrulnikov-rats-attested-inference-receipt-00`

## Body (draft)

Hello RATS WG,

I would appreciate feedback on `draft-tsyrulnikov-rats-attested-inference-receipt-00`:

https://datatracker.ietf.org/doc/draft-tsyrulnikov-rats-attested-inference-receipt/

AIR defines an application-layer EAT/CWT profile for **per-inference** receipts. The goal is to carry a signed record of one inference event that binds:

- model identity / hash
- request and response hashes
- attestation-linked metadata
- limited runtime fields

The scope is intentionally narrow:

- one receipt per inference
- COSE_Sign1 envelope with CWT/EAT claims
- attestation-linked, but not a replacement for platform-specific attestation verification
- not an Attestation Result format
- not transport, appraisal policy, or transparency-log protocol

The main questions I would value feedback on are:

1. Does this kind of per-inference evidence artifact fit the RATS problem space?
2. Is the current role split reasonable, where AIR-local verification is separate from platform-specific attestation verification and key binding?
3. Does the current claim shape look like a reasonable use of CWT/EAT for this scope?

IPR disclosure:
https://datatracker.ietf.org/ipr/7182/

I have also reviewed `draft-messous-eat-ai` and see AIR as complementary: AIR is focused on per-inference execution evidence rather than general AI-agent identity or provenance claims.

Thanks for any feedback.

Borys Tsyrulnikov
Cyntrisec

## Notes Before Sending

- Keep the first post architectural. Do not add compliance, healthcare, legal, or NIST framing.
- Do not mention local `-01` until it is actually posted.
- If challenged on charter fit, answer narrowly: AIR is an application-layer EAT/CWT profile for per-inference evidence, not an Attestation Result format or appraisal-policy protocol.
- If challenged on "why not just attestation + logs?", answer: platform evidence proves workload state; ordinary logs are implementation-specific and often unsigned; AIR standardizes a signed per-inference artifact that a third party can verify independently.
- If challenged on malicious signers, answer: AIR only has end-to-end value when the receipt signing key is bound to an attested workload accepted by the verifier.
