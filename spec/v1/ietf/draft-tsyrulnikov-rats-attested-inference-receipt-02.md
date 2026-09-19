---
title: "Attested Inference Receipt (AIR): A COSE/CWT Profile for Confidential AI Inference"
abbrev: "AIR v1"
docname: draft-tsyrulnikov-rats-attested-inference-receipt-02
category: info
ipr: trust200902
submissiontype: IETF
area: Security
workgroup: RATS
keyword:
  - attestation
  - AI inference
  - receipt
  - COSE
  - CWT
  - EAT
  - confidential computing

stand_alone: yes
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
  -
    ins: B. Tsyrulnikov
    name: Borys Tsyrulnikov
    organization: Cyntrisec
    email: borys@cyntrisec.com

normative:
  RFC8032:
  RFC8392:
  RFC8610:
  RFC8949:
  RFC9052:
  RFC9334:
  RFC9711:
  FIPS180-4:
    title: "Secure Hash Standard (SHS)"
    author:
      org: National Institute of Standards and Technology
    date: 2015-08
    target: https://csrc.nist.gov/publications/detail/fips/180/4/final

informative:
  RFC7942:
  RFC9782:
  RFC9864:
  RFC9943:
  I-D.messous-eat-ai:
    title: "Entity Attestation Token (EAT) Profile for Autonomous AI Agents"
    author:
      -
        ins: A. Messous
      -
        ins: L. Morand
      -
        ins: P. C. Liu
    date: 2026
  I-D.sharif-ai-model-lifecycle-attestation:
    title: "Cryptographic Attestation for AI Model Lifecycle: From Training Data to Inference Output"
    author:
      -
        ins: R. Sharif
    date: 2026
  I-D.reddy-rats-key-binding:
    title: "Key Attestation for Entity Attestation Tokens (EAT)"
    author:
      -
        ins: T. Reddy
      -
        ins: H. Tschofenig
      -
        ins: T. Fossati
      -
        ins: I. Mihalcea
    date: 2026
  I-D.ietf-rats-reference-interaction-models:
    title: "Reference Interaction Models for Remote Attestation Procedures"
    author:
      -
        ins: H. Birkholz
      -
        ins: M. Eckel
      -
        ins: W. Pan
      -
        ins: E. Voit
    date: 2026
  I-D.ietf-rats-epoch-markers:
    title: "Epoch Markers"
    author:
      -
        ins: H. Birkholz
      -
        ins: T. Fossati
      -
        ins: W. Pan
      -
        ins: I. Mihalcea
      -
        ins: C. Bormann
    date: 2026
  I-D.ietf-rats-eat-measured-component:
    title: "Entity Attestation Token (EAT) Measured Component"
    author:
      -
        ins: S. Frost
      -
        ins: T. Fossati
      -
        ins: H. Tschofenig
      -
        ins: H. Birkholz
    date: 2026
  I-D.ietf-scitt-receipts-ccf-profile:
    title: "CCF Profile for COSE Receipts"
    author:
      -
        ins: H. Birkholz
      -
        ins: A. Delignat-Lavaud
      -
        ins: C. Fournet
      -
        ins: A. Chamayou
    date: 2026
  I-D.kamimura-scitt-refusal-events:
    title: "Verifiable AI Refusal Events using SCITT"
    author:
      -
        ins: T. Kamimura
    date: 2026
  I-D.ietf-rats-multi-verifier:
    title: "Remote Attestation with Multiple Verifiers"
    author:
      -
        ins: Y. Deshpande
      -
        ins: J. Zhang
      -
        ins: H. Labiod
      -
        ins: H. Birkholz
    date: 2026
  I-D.richardson-rats-composite-attesters:
    title: "Taxonomy of Composite Attesters"
    author:
      -
        ins: M. Richardson
      -
        ins: H. Birkholz
      -
        ins: Y. Deshpande
      -
        ins: T. Fossati
    date: 2026
  I-D.poirier-rats-eat-da:
    title: "An EAT Profile for Trustworthy Device Assignment"
    author:
      -
        ins: M. Poirier
      -
        ins: H. Birkholz
      -
        ins: T. Fossati
    date: 2026
  I-D.ietf-rats-msg-wrap:
    title: "RATS Conceptual Messages Wrapper (CMW)"
    author:
      -
        ins: H. Birkholz
      -
        ins: N. Smith
      -
        ins: T. Fossati
      -
        ins: H. Tschofenig
      -
        ins: D. Glaze
    date: 2026
  I-D.ietf-rats-ear:
    title: "EAT Attestation Results"
    author:
      -
        ins: T. Fossati
      -
        ins: E. Voit
      -
        ins: S. Trofimov
      -
        ins: H. Birkholz
    date: 2026
  SCITT:
    title: "Supply Chain Integrity, Transparency and Trust (SCITT)"
    target: https://datatracker.ietf.org/wg/scitt/about/

--- abstract

This document defines the Attested Inference Receipt (AIR), an
application-layer COSE_Sign1 envelope carrying CWT claims profiled
per the Entity Attestation Token (EAT) framework. An AIR receipt
binds model identity, input/output hashes, attestation-linked
metadata, and operational telemetry into a single signed artifact
suitable for independent third-party verification of a confidential
AI inference. An AIR receipt is Attester-signed Evidence, not an
appraisal verdict: a RATS Verifier must appraise the referenced platform
attestation before the receipt establishes TEE provenance.

AIR v1 targets single-inference receipts emitted by workloads running
inside hardware-isolated Trusted Execution Environments (TEEs). AIR
is attestation-linked: it carries measurements and a hash reference to
the platform attestation evidence associated with the inference, but
it does not replace platform-specific attestation verification. This
version defines AWS Nitro Enclaves and Intel TDX measurement profiles
only, and assumes a single platform attestation document per receipt.
Pipeline chaining, multi-inference receipts, composite attesters,
multi-verifier orchestration, accelerator / GPU confidential-compute
attestation integration, and extensibility mechanisms for additional
claim or platform profiles are out of scope.

--- middle

# Introduction

Deployments that run machine learning models on cloud infrastructure
lack a standardized, interoperable mechanism to prove what happened
during a specific inference. Existing attestation frameworks such as
RATS {{RFC9334}} establish platform identity and code integrity, but
they do not produce per-inference evidence binding a model, its
inputs and outputs, and the platform state into a single verifiable
artifact.

Platform attestation and ordinary logs are both necessary but
insufficient for this purpose. Platform attestation proves properties
of the workload and its execution environment, typically at a point in
time, while ordinary logs are implementation-specific and often
unsigned. Neither provides a standard, portable object that binds one
inference event to model identity, request/response hashes, and
attestation-linked metadata in a form a third party can verify
independently of the underlying platform.

The Attested Inference Receipt (AIR) fills this gap. An AIR receipt is
an application-layer COSE_Sign1 {{RFC9052}} envelope whose payload is
a CWT {{RFC8392}} claims set profiled as an EAT {{RFC9711}}. The
receipt is signed with Ed25519 {{RFC8032}} by the workload running
inside a Trusted Execution Environment (TEE). AIR verification is
split into two concerns: AIR-local verification of the signed receipt
itself, and platform-specific verification of the underlying
attestation evidence and key binding. This document standardizes the
former and references the latter, but does not replace platform-
specific attestation procedures.

AIR v1 is scoped to a single inference: one request processed by one
model inside one attested workload produces one receipt. Pipeline
chaining, multi-stage proofs, and integration with transparency logs
(such as SCITT {{SCITT}}) are deferred to future versions.

## Goals

The goals of AIR v1 are:

1.  Define a receipt wire format using existing IETF standards
    (COSE_Sign1, CWT, EAT).

2.  Bind model identity (cryptographic hash), input/output hashes,
    attestation metadata, and operational telemetry in a single
    signed envelope.

3.  Support AIR-local verification using standard COSE/CWT tooling,
    while allowing deployments to combine AIR with separate
    platform-specific attestation verification as needed.

4.  Carry platform measurements in a portable receipt shape while
    preserving their platform-specific semantics via
    `measurement_type`.

5.  Define an intentionally closed v1 profile with fail-closed
    parsing semantics.

## Non-Goals {#non-goals}

AIR v1 explicitly does not:

-   Define a transport protocol or session management scheme.
-   Specify attestation document verification procedures (these are
    platform-specific).
-   Define an extension registry or compatibility mechanism for new
    claim or platform profiles.
-   Prove data deletion or model correctness.
-   Provide regulatory certification or compliance guarantees.
-   Define pipeline chaining or multi-inference receipts.
-   Support composite attesters with multiple distinct attestation
    documents per receipt (e.g., CPU TEE + GPU confidential compute).
    Workloads running on accelerator-equipped platforms such as
    NVIDIA H100 Confidential Compute can emit AIR v1 receipts, but
    those receipts cover only the CPU-side attestation; accelerator
    attestation is verified out of band and is not embedded in the
    receipt. A future composite-attester AIR profile would pair the
    CPU-side receipt with device-side Evidence such as the EAT Device
    Assignment profile ({{I-D.poirier-rats-eat-da}}); the RATS
    Conceptual Messages Wrapper ({{I-D.ietf-rats-msg-wrap}}) is a
    candidate standard conveyance for carrying platform Evidence and an
    AIR receipt together. An AIR v1 receipt emitted on such a platform
    MUST NOT be presented as evidence that the accelerator was in a
    confidential-computing mode; see {{accelerator-scope}}.
-   Define verifier-emitted Attestation Results. Where a deployment
    needs a Verifier-signed appraisal alongside an AIR receipt, an
    EAT Attestation Result (EAR, draft-ietf-rats-ear) is the natural
    complement.


# Requirements Language

{::boilerplate bcp14-tagged}


# Terminology {#terminology}

In this document, the term "verifier" (lowercase, or "Verifiers" when
used at the start of a sentence) refers to the AIR Receipt Validator
defined below. This is distinct from the RATS Verifier role defined
in {{RFC9334}} Section 4.1. Where this document needs to refer to the
RATS Verifier role, it uses the explicit phrase "RATS Verifier."

Attested Inference Receipt (AIR):
: An application-layer COSE_Sign1 signed CWT/EAT artifact emitted by
  a workload after processing a single AI inference request inside a
  TEE. The receipt binds model identity, input/output hashes,
  attestation-linked metadata, and operational telemetry.

Confidential Workload:
: The software executing inside a TEE that loads a model, processes
  inference requests, and generates AIR receipts. In RATS
  {{RFC9334}} terminology, the confidential workload acts as the
  Attester.

AIR Receipt Validator:
: An entity that performs AIR-local checks on a receipt: COSE
  signature verification, claim structure validation, and policy
  evaluation on receipt contents (see {{verification-procedure}}).
  The AIR Receipt Validator is distinct from the RATS Verifier role
  in {{RFC9334}} Section 4.1. A RATS Verifier appraises Evidence
  against reference values and endorsements to produce Attestation
  Results; the AIR Receipt Validator does not perform that appraisal.
  Full TEE assurance additionally requires platform-specific
  verification of the underlying attestation evidence and
  signing-key binding; those procedures are outside AIR-local
  verification and are performed by a RATS Verifier using
  platform-specific procedures.

Relying Party:
: An entity that consumes AIR receipts (together, where applicable,
  with platform Attestation Results) to make trust decisions (e.g.,
  an auditor, compliance officer, or end user). In RATS {{RFC9334}}
  terminology, this maps to the Relying Party role.

Endorser:
: The TEE hardware vendor (e.g., AWS for Nitro, Intel for TDX) whose
  attestation infrastructure anchors trust in the platform
  measurements carried by the receipt.

Measurement Map:
: The `enclave_measurements` claim containing platform-specific
  register values carried in portability-oriented slots. The
  `measurement_type` field determines the actual semantics of those
  slots on each platform.

Receipt:
: In this document, "receipt" always refers to an AIR receipt. Note
  that this differs from the SCITT usage of "receipt" (which refers
  to a countersigned statement from a transparency service). The two
  are complementary: a future version could register an AIR receipt
  with a SCITT transparency service and receive a SCITT receipt in
  return.


# AIR v1 Receipt Format

## COSE_Sign1 Envelope

An AIR v1 receipt is a tagged COSE_Sign1 structure (CBOR tag 18) as
defined in {{RFC9052}} Section 4.2:

~~~
COSE_Sign1 = [
  protected   : bstr,          ; serialized protected header
  unprotected : map,            ; unprotected header map
  payload     : bstr,           ; serialized CWT claims map
  signature   : bstr .size 64   ; Ed25519 signature
]
~~~

The signature covers `Sig_structure = ["Signature1", protected,
external_aad, payload]` where `external_aad` is empty (`h''`).

Verifiers MUST reject untagged COSE_Sign1 structures. The CBOR tag 18
is mandatory.

## Protected Header

The protected header is a CBOR map containing exactly two entries:

| Label | Name           | Value | Description                    |
|------:|:---------------|------:|:-------------------------------|
|     1 | alg            |    -8 | EdDSA (Ed25519)                |
|     3 | content type   |    61 | application/cwt                |

Verifiers MUST reject receipts where `alg` is not -8 or where
`content type` is not 61. Additional protected header parameters are
not defined in v1 and MUST NOT be present.

The signing algorithm is Ed25519 ({{RFC8032}}). Receipts MUST be
verified with the strict procedure specified in
{{verification-procedure}}, Layer 2: a non-canonical scalar S (S
outside \[0, L), where L is the Ed25519 group order), a small-order R
or A point, and any signature failing the cofactorless group equation
are all rejected. This is stricter than the baseline verification of
{{RFC8032}} Section 5.1.7.

## Unprotected Header

The unprotected header MUST be empty for AIR v1 receipts. AIR v1 does
not use `kid` or any other unprotected header parameter. Because
unprotected header parameters are not covered by the COSE signature,
verifiers MUST reject receipts with non-empty unprotected headers.

## Payload: CWT Claims Map

The payload is a CBOR-encoded CWT claims map. The map uses
deterministic encoding per {{RFC8949}} Section 4.2.1: map keys are
sorted in the bytewise lexicographic order of their encoded form.

The claims map is closed: verifiers MUST reject maps containing
unknown integer keys. Duplicate keys MUST be rejected.

## CDDL Schema {#cddl}

The following CDDL {{RFC8610}} defines the complete wire shape:

~~~ cddl
air-receipt = #6.18([
  protected:   bstr .cbor air-protected-header,
  unprotected: air-unprotected-header,
  payload:     bstr .cbor air-claims,
  signature:   bstr .size 64
])

air-protected-header = {
  1 => -8,          ; alg: EdDSA (Ed25519)
  3 => 61,          ; content type: application/cwt
}

air-unprotected-header = {}

air-claims = {
  ; --- Standard CWT/EAT claims ---
  1   => tstr,                  ; iss: issuer
  6   => uint,                  ; iat: issued-at (Unix seconds)
  7   => bstr .size 16,         ; cti: CWT ID (UUID v4, 16 bytes)
  265 => "https://spec.cyntrisec.com/air/v1",  ; eat_profile
  ? 10 => bstr .size (8..64),   ; eat_nonce (optional)

  ; --- AIR private claims ---
  -65537 => tstr,               ; model_id
  -65538 => tstr,               ; model_version
  -65539 => sha256-hash,        ; model_hash
  -65540 => sha256-hash,        ; request_hash
  -65541 => sha256-hash,        ; response_hash
  -65542 => sha256-hash,        ; attestation_doc_hash
  -65543 => enclave-measurements, ; enclave_measurements
  -65544 => tstr,               ; policy_version
  -65545 => uint,               ; sequence_number
  -65546 => uint,               ; execution_time_ms
  -65547 => uint,               ; memory_peak_mb
  -65548 => tstr,               ; security_mode
  ? -65549 => tstr,             ; model_hash_scheme (optional)
}

sha256-hash = bstr .size 32
sha384-hash = bstr .size 48

enclave-measurements = nitro-measurements / tdx-measurements

nitro-measurements = {
  "pcr0"             => sha384-hash,   ; image
  "pcr1"             => sha384-hash,   ; kernel + ramdisk
  "pcr2"             => sha384-hash,   ; application
  ? "pcr3"           => sha384-hash,   ; IAM role (optional)
  ? "pcr4"           => sha384-hash,   ; instance identity (optional)
  ? "pcr8"           => sha384-hash,   ; signing cert (optional)
  "measurement_type" => "nitro-pcr",
}

tdx-measurements = {
  "pcr0"             => sha384-hash,   ; MRTD
  "pcr1"             => sha384-hash,   ; RTMR0
  "pcr2"             => sha384-hash,   ; RTMR1
  ? "pcr3"           => sha384-hash,   ; RTMR2 (optional)
  ? "pcr4"           => sha384-hash,   ; RTMR3 (optional)
  "measurement_type" => "tdx-mrtd-rtmr",
}
~~~

The full CDDL is also provided in {{appendix-cddl}}.


# Claim Semantics

## Standard CWT/EAT Claims

### iss (Issuer) -- key 1

A text string identifying the issuing entity (e.g.,
`"cyntrisec.com"`). The value is operator-assigned and opaque to the
receipt format. Verifiers MAY check against an expected issuer
allowlist.

### iat (Issued At) -- key 6

An unsigned integer representing the Unix timestamp (seconds since
epoch) when the inference completed. Verifiers apply a freshness
check: `now - max_age <= iat <= now + clock_skew`. Verifiers SHOULD
reject future timestamps.

### cti (CWT ID) -- key 7

A 16-byte binary string that uniquely identifies the receipt. Each
receipt MUST have a unique `cti`. Implementations SHOULD derive `cti`
from a cryptographically random source; UUID v4 encoded as raw bytes
(not the 36-character string form) is RECOMMENDED. Other 16-byte
unique identifiers (for example, the first 128 bits of a randomly
drawn 256-bit value) are acceptable.

Verifiers maintaining replay state SHOULD track observed `cti`
values and reject duplicates.

### eat_profile -- key 265

The fixed string value `"https://spec.cyntrisec.com/air/v1"`.
Verifiers MUST reject receipts with unknown eat_profile values.

### eat_nonce -- key 10

An optional binary string (8-64 bytes per {{RFC9711}} Section 4.1)
provided by the verifier or relying party to bind the receipt to a
specific request session. Per {{RFC9711}} Section 4.1 the nonce MUST
have at least 64 bits of entropy. The nonce MUST be supplied by the
party checking freshness; an Attester-generated nonce provides no
replay protection. If the verifier supplied a nonce, it MUST check that
eat_nonce matches. This is the primary replay resistance mechanism
when verifier-side cti deduplication is not feasible.

## AIR Private Claims

AIR uses negative integer keys in the CWT private-use range to
avoid collision with IANA-registered claims. Keys -65537 through
-65548 are assigned and required. Key -65549 is assigned and
optional. No other AIR private claim keys are defined in v1.

### model_id -- key -65537

A text string containing the human-readable model identifier (e.g.,
`"minilm-l6-v2"`). Operator-assigned, opaque. Not cryptographic; use
model_hash for binding.

### model_version -- key -65538

A text string containing the human-readable model version (e.g.,
`"1.0.0"`). Operator-assigned, opaque.

### model_hash -- key -65539

A 32-byte SHA-256 {{FIPS180-4}} binding for the model artifact set
used for the inference. If `model_hash_scheme` is present, it defines
how this binding was computed; if `model_hash_scheme` is absent,
verifiers SHOULD treat `model_hash` as an opaque model-identity value
that can still be compared against a known-good reference hash.

This claim is application-layer model identity evidence. It does not
by itself prove that the referenced model artifacts were loaded or
executed under hardware attestation; that stronger conclusion requires
independent verification of the attested workload and its relation to
the application-layer model-loading path. The model_hash MUST NOT be
all zeros.

### request_hash -- key -65540

A 32-byte SHA-256 hash of the inference request payload. Binds the
receipt to a specific input. Clients holding the original request
can recompute and compare.

### response_hash -- key -65541

A 32-byte SHA-256 hash of the inference response payload. Binds the
receipt to a specific output.

`request_hash` and `response_hash` commit to specific input and output
byte strings. They do not prove that the response is the model's output
for that input, and each hash is computed over the request or response
payload as the workload defines it, which MAY differ from the
pre-processed (for example, tokenized or normalized) bytes the model
actually consumed or produced.

### attestation_doc_hash -- key -65542

A 32-byte SHA-256 digest that links the receipt to the platform
attestation document without embedding the (potentially large)
document itself.

The hash preimage is the raw attestation artifact, pinned per
platform:

-   **AWS Nitro Enclaves:** SHA-256 of the NSM attestation document --
    the COSE_Sign1 byte string returned by the Nitro Security Module,
    hashed exactly as returned, with no re-encoding.

-   **Intel TDX:** SHA-256 of the raw DCAP quote -- the TDX quote
    structure, header through quote signature, as produced by the
    platform. The preimage is the quote bytes alone: it MUST NOT
    include any transport framing wrapped around the quote, and MUST
    NOT include DCAP collateral (certificate chains, TCB info, QE
    identity, or CRLs).

`attestation_doc_hash` binds the receipt to the attestation artifact
bytes themselves. It does not bind to collateral bundles, to verifier
policy, or to any derived measurement summary; those are obtained and
appraised separately.

The TDX quote version (for example, v4 or v5) is not carried as a
separate AIR v1 claim. A verifier that needs the version parses it
from the quote bytes it obtains and hashes. A future AIR profile may
add explicit attestation metadata for this purpose.

AIR v1 does not define attestation document verification. A verifier
reproduces this digest by obtaining the same raw attestation artifact;
it SHOULD also independently verify that artifact -- its signature and
trust chain -- before relying on it, then compare the artifact's
SHA-256 to this claim.

For a receipt asserting end-to-end TEE provenance, `attestation_doc_hash`
MUST reference the same attestation document that carries the
signing-key binding of {{key-binding}} and the measurement registers
reconciled by the validator (see {{validator-behavior}}). A receipt used
only as an application-layer signed log (AIR-local, asserting no TEE
provenance) MAY reference a different or boot-time document, but MUST NOT
be presented as TEE-provenance evidence. A split model that combines a
boot-time `attestation_doc_hash` with a separate per-session key-binding
quote is out of scope for AIR v1 and may be defined by a future profile.

Even in the single-document model, the attestation is typically captured
at workload start, not per inference. A provenance-checked AIR receipt
therefore demonstrates that a key bound to an attested workload signed
these claims; it does NOT by itself demonstrate that this specific
inference executed at the time the attestation was captured. Deployments
needing per-inference or contemporaneous binding require a mechanism
beyond AIR v1 (a fresh per-session attestation, or the external
transparency/sequencing layer discussed in {{replay-protection}}).

A conformant AIR receipt MUST set `attestation_doc_hash` to the
per-platform preimage defined above. Populating the field with any
other value -- for example, a digest of the receipt signing key used
as an internal placeholder -- does not produce a conformant
attestation-bound AIR receipt, and such a receipt MUST NOT be
presented as one.

### enclave_measurements -- key -65543 {#measurements}

A map containing platform-specific measurement registers. The map
structure depends on the `measurement_type` field within it.

#### Nitro PCR Variant (measurement_type = "nitro-pcr")

| Field              | Type    | Required | Description                 |
|:-------------------|:--------|:---------|:----------------------------|
| `"pcr0"`           | bstr 48 | Yes      | PCR0 (image)                |
| `"pcr1"`           | bstr 48 | Yes      | PCR1 (kernel + ramdisk)     |
| `"pcr2"`           | bstr 48 | Yes      | PCR2 (application)          |
| `"pcr3"`           | bstr 48 | No       | PCR3 (IAM role)             |
| `"pcr4"`           | bstr 48 | No       | PCR4 (instance identity)    |
| `"pcr8"`           | bstr 48 | No       | PCR8 (signing certificate)  |
| `"measurement_type"` | tstr | Yes      | `"nitro-pcr"`               |

PCR3 and PCR4 are OPTIONAL and RECOMMENDED for multi-tenant
deployments where IAM role and instance identity are part of the
trust decision. PCR8 is OPTIONAL and RECOMMENDED when the deployment
relies on a signing-certificate measurement. Absence of an optional
PCR does not invalidate the receipt; verifiers MAY require specific
optional PCRs by local policy.

#### TDX MRTD/RTMR Variant (measurement_type = "tdx-mrtd-rtmr")

| Field              | Type    | Required | Description       |
|:-------------------|:--------|:---------|:------------------|
| `"pcr0"`           | bstr 48 | Yes      | MRTD              |
| `"pcr1"`           | bstr 48 | Yes      | RTMR0             |
| `"pcr2"`           | bstr 48 | Yes      | RTMR1             |
| `"pcr3"`           | bstr 48 | No       | RTMR2 (optional)  |
| `"pcr4"`           | bstr 48 | No       | RTMR3 (optional)  |
| `"measurement_type"` | tstr | Yes      | `"tdx-mrtd-rtmr"` |

TDX exposes four Runtime Measurement Registers (RTMR0 through RTMR3).
RTMR2 and RTMR3 are OPTIONAL in AIR v1: RTMR2 is commonly extended by
the guest runtime (container platforms, language runtimes) and
RTMR3 by the workload itself. Deployments that extend either register
as part of their trust model SHOULD include the corresponding value
in the receipt. Absence of an optional RTMR does not invalidate the
receipt; verifiers MAY require specific optional RTMRs by local
policy.

The TDX registers are mapped to `pcr0`/`pcr1`/`pcr2`/`pcr3`/`pcr4`
portability slots for cross-platform verifier simplicity. The
`measurement_type` field disambiguates the actual register semantics.
These slot names do not imply that Nitro PCRs and TDX MRTD/RTMRs are
semantically identical.

Future AIR revisions may carry measurements via the EAT Measured
Component claim ({{I-D.ietf-rats-eat-measured-component}}) once that
work is published. AIR v1 uses the bespoke map above to avoid taking
a dependency on a not-yet-RFC document.

All measurement values present in the map (whether required or
optional) MUST be exactly 48 bytes. Verifiers MUST reject receipts
where any measurement register is the wrong length. The
`measurement_type` MUST be one of the defined values; unknown types
MUST be rejected.

### policy_version -- key -65544

A text string identifying the version of the policy governing the
workload (e.g., `"policy-2026.02"`). Informational.

### sequence_number -- key -65545

An unsigned integer that SHOULD increase by one for each receipt
produced within a single workload session, resetting on workload
restart.

This claim is **informational only**. It is not a cryptographic
freshness or replay-protection mechanism:

-   `sequence_number` is signed as part of the receipt, but a
    compromised workload can emit any value it chooses.
-   `sequence_number` resets on workload restart, so it provides no
    cross-session ordering.
-   Gaps in `sequence_number` MAY indicate missed receipts within a
    session but are NOT a receipt-verification failure.

Verifiers MUST NOT treat `sequence_number` in isolation as evidence
of freshness or as a replay-detection signal. Replay resistance
comes from `cti` deduplication and, where applicable, `eat_nonce`
challenge-binding; see {{replay-protection}}.

### execution_time_ms -- key -65546

An unsigned integer representing the wall-clock inference time in
milliseconds. Informational; anomalously low or high values may
indicate issues but are not a verification failure.

### memory_peak_mb -- key -65547

An unsigned integer representing the peak memory usage during
inference in megabytes. Informational.

### security_mode -- key -65548

A text string identifying the security mode of the emitting workload.
AIR v1 defines a closed set of values; verifiers MUST reject receipts
whose `security_mode` is outside this set (fail-closed, same pattern
as `model_hash_scheme`, {{mhscheme}}).

Defined values:

| Value          | Meaning                                                   |
|:---------------|:----------------------------------------------------------|
| `"production"` | Workload runs in a production configuration.              |
| `"evaluation"` | Workload runs in an evaluation / demonstration configuration. Receipts with `security_mode` = `"evaluation"` MUST NOT be accepted by verifiers configured for production trust decisions. |

Verifiers MAY additionally enforce deployment-specific policy on
`security_mode`; for example, a verifier configured for production
use MUST reject receipts whose `security_mode` is `"evaluation"`, and MAY
reject receipts whose `security_mode` is any value other than an
allowlisted production set.

No other `security_mode` values are defined in AIR v1. Future
revisions MAY define additional values. AIR v1 implementations MUST
NOT invent new values; an implementation needing a value outside the
defined set should use a future AIR revision or a vendor-specific
extension outside the AIR profile.

The `security_mode` claim is self-asserted: it is written and signed by
the workload and states only the configuration the workload believes it
is in. It is not the output of any appraisal and conveys no positive
assurance. A Verifier or Relying Party MUST NOT treat any `security_mode`
value -- including `"production"` -- as evidence of a secure or
production posture, and MUST NOT base a positive trust decision on it.
Its only sound use is fail-closed: a verifier configured for production
trust decisions MUST reject `"evaluation"` (and MAY reject any
non-allowlisted value), so that a receipt an honest workload self-marks
as non-production cannot be accepted. A workload's actual security
posture is established solely by verifying the referenced platform
attestation and appraising its measurements, TCB, and debug state
against reference values (see {{validator-behavior}}).

This design is deliberate. Earlier EAT work carried a self-asserted
`security-level` claim that the RATS working group removed before
RFC 9711, precisely because a device asserting its own security level
proves nothing. `security_mode` is not a graded positive security
level; it is a binary fail-closed sentinel whose only effect is to let
an honest emitter downgrade itself (`"evaluation"`) so verifiers reject
it. A lying workload gains nothing by writing `"production"`, because no
positive weight is placed on the value: trust comes only from the
attestation appraisal (see {{claim-trust-classes}}).

Product- or deployment-specific submodes (for example, vendor-defined
production profiles) are out of scope for AIR v1. Implementations
needing such distinctions SHOULD map them to the generic AIR v1 value
space for interoperability.

### model_hash_scheme -- key -65549 {#mhscheme}

An optional text string declaring how model_hash was computed,
enabling verifiers to reproduce the hash from model artifacts.

Defined scheme values:

| Scheme              | Description                                |
|:--------------------|:-------------------------------------------|
| `"sha256-single"`   | SHA-256 of a single model weights file |
| `"sha256-concat"`   | SHA-256 of deterministically concatenated model weight files (lexicographic filename order) |
| `"sha256-manifest"` | SHA-256 of a self-describing manifest that identifies the model artifact set (for example, weights files and associated tokenizer or configuration artifacts) via per-file hashes |

If present, verifiers MUST recognize the scheme value. Unknown
schemes MUST be rejected (fail-closed). If absent, verifiers SHOULD
treat model_hash as opaque (can still compare against a known-good
hash, but cannot independently reproduce it).

No additional scheme values are defined in AIR v1. Future revisions
MAY define more scheme values. AIR v1 implementations MUST NOT invent
new scheme values.


# EAT Profile Declaration

{{RFC9711}} Section 6.2 requires a full profile to be complete enough
that a receiver can decode, verify, and check the freshness of a
receipt; Section 6.3 lists the profile issues a profile should address.
This section states AIR v1's position on each.

1.  **Profile identifier**: URI
    `"https://spec.cyntrisec.com/air/v1"` (carried in eat_profile,
    key 265).

2.  **Encoding**: CBOR only ({{RFC8949}}). JSON serialization is not
    defined.

3.  **Envelope**: COSE_Sign1 ({{RFC9052}} Section 4.2), CBOR tag 18.
    Untagged COSE_Sign1 MUST be rejected.

4.  **Payload content type**: COSE content_type = 61
    (`application/cwt`). The payload is a CWT claims map.

5.  **HTTP media type**: `application/eat+cwt` ({{RFC9782}}).
    Receivers SHOULD accept both `application/cwt` and
    `application/eat+cwt`. Senders MAY include the `eat_profile`
    media-type parameter defined by {{RFC9782}} --
    `application/eat+cwt; eat_profile="https://spec.cyntrisec.com/air/v1"`
    -- so that receivers can route on the profile without decoding the
    receipt body. An AIR receipt MAY also be carried inside a RATS
    Conceptual Messages Wrapper ({{I-D.ietf-rats-msg-wrap}}) when it is
    conveyed alongside other attestation messages.

6.  **Signing algorithm**: Ed25519 only (COSE alg = -8). Signatures
    MUST be verified with the strict procedure of
    {{verification-procedure}}, Layer 2 (canonical scalar S,
    small-order R/A rejection, cofactorless group equation). No
    algorithm negotiation in v1.

7.  **Detached bundles**: Not supported in v1. The attestation
    document is referenced by hash (attestation_doc_hash), not
    embedded.

8.  **Key identification**: Out of band. The verifier obtains the
    Ed25519 public key through a platform-specific channel (e.g.,
    attestation document, key registry). AIR v1 does not use `kid`.

9.  **Mandatory claims**: 16 required claims: iss, iat, cti,
    eat_profile, model_id, model_version, model_hash, request_hash,
    response_hash, attestation_doc_hash, enclave_measurements,
    policy_version, sequence_number, execution_time_ms,
    memory_peak_mb, security_mode.

10. **Optional claims**: 2 optional claims: eat_nonce (replay
    resistance), model_hash_scheme (hash computation method).

11. **Freshness**: `iat` carries the execution timestamp (Unix
    seconds). Verifiers apply `max_age` + `clock_skew` policy.
    `eat_nonce` provides optional challenge-response replay
    resistance ({{RFC9711}} Section 4.1, 8-64 bytes).

12. **Deterministic encoding**: Required. Map keys sorted per
    {{RFC8949}} Section 4.2.1 (bytewise lexicographic order of the
    encoded map keys).

13. **Closed claims map**: The claims map is closed. Unknown integer
    keys MUST be rejected. Duplicate keys MUST be rejected.

14. **Unprotected header**: MUST be empty. All header parameters are
    carried in the protected header. Receipts with non-empty
    unprotected headers MUST be rejected.

15. **Private claim keys**: Keys -65537 through -65549 are assigned
    in the CWT private-use range ({{RFC8392}}). No IANA registration
    is required. AIR v1 defines no extension mechanism or additional
    private claim keys beyond this set.

16. **Endorsement / reference-value identification**: Out of scope for
    the AIR receipt. An AIR receipt carries no endorsement or
    reference-value identifiers; reference values and endorsements are
    supplied to and appraised by a RATS Verifier (see
    {{validator-behavior}} and Trust Assumption TA-4 in
    {{trust-assumptions}}), not by the AIR Receipt Validator, keeping
    the receipt strictly Evidence and not an Attestation Result. The
    standard EAT entity-identity claims (`ueid`, `sueids`, `oemid`,
    `hwmodel`, `hwversion`) are not used and are prohibited by the
    closed claims map.


# Key Binding {#key-binding}

AIR-local verification (see {{verification-procedure}}) does not
require any particular relationship between the Ed25519 signing key
and the underlying platform attestation. Deployments that use AIR
receipts purely as a signed log of application-layer claims, without
asserting TEE provenance, may operate without key binding.

However, a common and load-bearing deployment model uses the AIR
receipt as evidence that a specific inference ran inside a specific
attested workload. For that model, end-to-end TEE provenance is only
sound when the signing key is cryptographically bound to the attested
workload. Deployments that assert such end-to-end TEE provenance MUST
bind the Ed25519 signing key to accepted platform attestation evidence
via an out-of-band cryptographic construction.

## Single-Purpose Signing Key

The Ed25519 key bound to the platform attestation is a single-purpose
AIR receipt signing key.

-   The key MUST be used only to produce the signature of an AIR
    COSE_Sign1 receipt: the Ed25519 signature over the receipt's COSE
    `Sig_structure` ({{RFC9052}} Section 4.4) for the AIR profile named
    in the receipt's `eat_profile` claim.
-   The key MUST NOT be reused for any other purpose. In particular it
    MUST NOT be used for transport-layer handshakes, attestation or
    key-exchange protocols, JWT or other token signing,
    transparency-log or audit-log signing, general-purpose Ed25519
    signatures, or any other application protocol.
-   An implementation that needs a signing key for any additional role
    MUST generate and separately attest a distinct key, or derive a
    distinct key under a separate, domain-separated key schedule. It
    MUST NOT repurpose the attested AIR signing key.

With this restriction, every signature the attested key can produce is
an AIR receipt for the advertised profile, so an attested AIR signature
is unambiguous.

## Conformant Constructions

The following constructions satisfy the key binding requirement above
when the associated attestation is verified by a RATS Verifier against
the platform's trust chain:

1.  **AWS Nitro Enclaves:** generate the Ed25519 receipt signing key
    inside the enclave and carry either its 32-byte public key, or an
    unambiguous encoded structure containing it, in the `user_data`
    field of the NSM attestation document. The Nitro Security Module
    signs the document, including `user_data`, so the receipt signing
    key is covered by the hardware-rooted signature. A verifier
    validates the document against the AWS Nitro root and checks that
    the receipt signing key carried in `user_data` matches the public
    key used to verify the AIR signature.

2.  **Intel TDX:** generate the Ed25519 receipt signing key inside the
    Trusted Domain and bind it into the TDX quote's 64-byte
    REPORTDATA. Because REPORTDATA is fixed at 64 bytes, the binding
    is a SHA-512 digest -- placed as the full REPORTDATA -- over a
    domain-separated, length-prefixed encoding of: a domain label,
    the platform identifier, the protocol version, the transport
    handshake public key, the Ed25519 receipt signing key, the
    session nonce, and an optional platform-evidence hash.

    To make the binding independently reproducible, one interoperable
    construction pins the SHA-512 preimage exactly as the concatenation,
    in order, of: (1) the domain label, length-prefixed; (2) the
    platform identifier (a UTF-8 string, for example `"gcp-cs-tdx"`),
    length-prefixed; (3) the protocol version as a 4-octet unsigned
    big-endian integer (fixed width, not length-prefixed); (4) the
    32-octet transport handshake public key, length-prefixed; (5) the
    32-octet Ed25519 receipt signing key, length-prefixed; (6) the
    32-octet session nonce, length-prefixed; and (7) a 1-octet
    platform-evidence flag -- `0x01` followed by the 32-octet
    platform-evidence hash when present, or `0x00` alone when absent.
    "Length-prefixed" means a 4-octet unsigned big-endian octet count
    immediately preceding the field it describes; the handshake key,
    receipt signing key, and nonce MUST each be exactly 32 octets. The
    REPORTDATA is the 64-octet SHA-512 digest of this preimage, and the
    domain label (for this construction, the ASCII string
    `"cyntrisec-tdx-envelope-v2"`) distinguishes it from any other use
    of the same input shape. A verifier
    validates the quote via DCAP against the Intel SGX and TDX trust
    chains, recomputes the SHA-512 binding from the attestation
    envelope's stated inputs, and rejects the quote unless the result
    equals the quote's REPORTDATA.

These constructions describe the key-binding attestation itself. In
AIR v1, whether a receipt's `attestation_doc_hash` references that
same per-session attestation -- rather than a separate boot-time
attestation -- is a profile-versioning question. For a receipt
asserting end-to-end TEE provenance, {{validator-behavior}} requires
`attestation_doc_hash` to reference the same document that carries this
key binding; a profile that separates the two (a boot-time
`attestation_doc_hash` plus a per-session key-binding quote) is out of
scope for AIR v1 and may be addressed by a future profile.

Other constructions MAY be used where the target attestation platform
supports them. Implementers SHOULD consult
{{I-D.reddy-rats-key-binding}} for a general treatment of key binding
in RATS as that work matures. The Nitro and TDX constructions above
instantiate the "combined" key-binding model of
{{I-D.reddy-rats-key-binding}} -- the attestation Evidence and the
key binding are produced together by the Attester -- and a future AIR
profile could align this binding with that draft's confirmation
(`cnf`) claim encoding once it stabilizes. AIR v1 binds the key through
the platform quote (REPORTDATA / `user_data`) rather than a receipt-level
`cnf` claim because the binding must be rooted in the hardware-signed
attestation itself: the Attester generates the ephemeral signing key
inside the TEE and commits it into the quote the vendor signs, which a
`cnf` claim signed only by the workload cannot by itself provide.

## Validator Behavior {#validator-behavior}

For the end-to-end TEE assurance procedure below, the attestation
document referenced by `attestation_doc_hash` MUST be the same document
that carries the key binding ({{key-binding}}) and the measurement
registers reconciled below. AIR v1 does not define a provenance
procedure for a deployment whose key-binding attestation and
`attestation_doc_hash` are different documents (for example, a
per-session key-binding quote plus a separate boot-time attestation);
such a split is left to a future profile.

An AIR Receipt Validator configured for end-to-end TEE assurance:

-   MUST obtain the platform attestation document referenced by
    `attestation_doc_hash` and validate it via platform-specific
    procedures before accepting the receipt.
-   MUST check the binding described in the construction above:
    the public key used to verify the AIR signature matches the
    public-key value embedded in the attestation document (or its
    hash, depending on the construction).
-   MUST reject the receipt if the binding check fails.
-   MUST reconcile the receipt's `enclave_measurements` claim against
    the measurement registers carried in the validated attestation
    document. Every measurement register present in
    `enclave_measurements` MUST equal, byte for byte, the
    corresponding register in the validated attestation document; a
    register that the attestation document does not expose cannot be
    reconciled. The validator MUST reject the receipt if any register
    in `enclave_measurements` is unequal to, or cannot be reconciled
    against, the validated attestation document (fail-closed). The
    `enclave_measurements` claim is signed only by the workload's own
    key; it is corroborated platform evidence only after this
    reconciliation succeeds (see {{claim-trust-classes}}).

-   MUST require the presence of every measurement register its policy
    deems security-critical, and MUST reject a receipt that omits such
    a register (fail-closed). Byte-for-byte reconciliation quantifies
    only over the registers present in `enclave_measurements`, and the
    emitting workload chooses that set; a validator that does not
    enforce required-register presence can be handed a receipt that
    omits a workload- or runtime-identifying register. On Intel TDX in
    particular, the application and guest-runtime measurements are
    carried in the OPTIONAL RTMR2/RTMR3 slots, so a validator asserting
    that a specific workload executed MUST require the register(s) that
    identify that workload rather than only the mandatory MRTD/RTMR0/
    RTMR1 platform registers.

-   MUST NOT treat successful reconciliation as workload
    acceptability. Reconciliation establishes only that the receipt's
    measurement values match the validated attestation document
    (hardware-rootedness), not that those values, the platform TCB, or
    the debug state are acceptable. A validator asserting end-to-end
    TEE assurance MUST additionally appraise the reconciled
    measurements and the platform TCB/debug state against its
    reference-value policy -- or defer that appraisal to a RATS
    Verifier that performs it -- and MUST reject unacceptable values.
    In particular, a validator asserting a production security posture
    MUST reject a TEE that reports a debug or development mode (for
    example, Intel TDX `TD_ATTRIBUTES.DEBUG` set, or an SGX enclave in
    DEBUG mode), and MUST reject a platform whose TCB is out of date or
    revoked, unless the deployment explicitly accepts such a platform
    for a non-production purpose.

-   MUST require the receipt to bind at least one freshness mechanism
    -- a verifier-supplied `eat_nonce` or `cti` deduplication -- before
    asserting end-to-end TEE provenance. {{RFC9711}} Section 9.3 requires
    an EAT to have a freshness mechanism to prevent replay and reuse; a
    provenance claim over a receipt carrying no freshness binding is
    vulnerable to replay of a pre-signed receipt (see
    {{replay-protection}}).

-   MUST, when the key-binding construction commits a session nonce into
    the platform quote (for example, TDX REPORTDATA) and the receipt
    also carries `eat_nonce`, check that the quote-bound nonce and
    `eat_nonce` are equal, so that the receipt and the underlying
    platform attestation share one freshness challenge.

An AIR Receipt Validator that does not require end-to-end TEE
assurance (for example, in a deployment that uses AIR only as a
signed log bound by application-layer trust decisions) MAY skip the
checks in this section (key binding, measurement reconciliation,
appraisal, and required-register presence). Such a validator MUST NOT
claim TEE provenance from the receipt alone.

# Verification Procedure {#verification-procedure}

The AIR v1 verification procedure is organized into four layers. The
checks proceed strictly in this order:

> COSE structure/header validation -> signature verification ->
> payload CBOR decode -> AIR claim validation ->
> relying-party policy checks

Layer 1 performs COSE structure and header validation; Layer 2 verifies
the signature; Layer 3 decodes the payload CBOR and then validates the
AIR claims; Layer 4 applies relying-party policy checks.

These layers define AIR-local verification only. A deployment that
requires full TEE assurance MUST additionally obtain and verify the
underlying platform attestation evidence and the binding between that
evidence and the AIR signing key using platform-specific procedures.

A conformant verifier MUST indicate, in its result, which assurance
level it established: AIR-local verification (Layers 1-4 of this
section only) or end-to-end TEE assurance (Layers 1-4 plus the full set
of checks in {{validator-behavior}} -- key binding, measurement
reconciliation, required-register presence, and measurement/TCB/debug
appraisal). An AIR-local result MUST NOT be presented or recorded as
TEE provenance.

Each AIR-local layer MUST complete successfully before proceeding to
the next. If any check fails, the verifier MUST reject the receipt and
SHOULD report the specific failure.

A verifier MUST NOT decode the payload CBOR or interpret any claim
value before the Layer 2 signature check succeeds. Layers 1 and 2
operate only on the COSE_Sign1 structure, the protected header, and the
payload as an opaque byte string; the CWT claims are decoded and
validated in Layer 3, only after the signature over them has been
verified.

## Layer 1: COSE Structure and Header Validation

1.  Decode the input as CBOR. Confirm the outer structure is tagged
    with CBOR tag 18.

2.  Decode the COSE_Sign1 array (4 elements).

3.  Confirm the receipt size does not exceed 65,536 bytes. This
    bound is a verifier-side denial-of-service guard; typical AIR v1
    receipts are under 1 KB. The bound applies to the serialized
    tagged COSE_Sign1 structure. Deployments requiring larger
    receipts (for example, with embedded certificate chains not
    defined in this version) MUST use a future AIR revision that
    specifies the additional payload.

4.  Decode the protected header. Confirm it is a well-formed CBOR
    map.

5.  Confirm `alg` (label 1) in the protected header is -8 (EdDSA).
    Reject receipts with any other algorithm.

6.  Confirm `content type` (label 3) in the protected header is 61
    (`application/cwt`).

7.  Confirm the unprotected header is empty.

The payload is carried through this layer as an opaque byte string; it
is not decoded until Layer 3, after signature verification.

## Layer 2: Signature Verification

1.  Construct Sig_structure = \["Signature1", protected, h'',
    payload\] per {{RFC9052}} Section 4.4. The result is the message M
    over which the signature is verified.

2.  Verify the Ed25519 signature -- the point R (first 32 octets) and
    the scalar S (last 32 octets) -- over M with the Ed25519 public
    key A. A conformant verifier MUST perform all of the following
    checks and MUST reject the receipt if any of them fails:

    a.  Decode S as a 32-octet little-endian integer. Reject unless
        0 <= S < L, where L is the order of the Ed25519 prime-order
        subgroup. A verifier MUST NOT reduce S modulo L; an S value
        outside \[0, L) is a verification failure.

    b.  Recover R and A as Edwards curve points from their 32-octet
        encodings. Reject the signature if either encoding does not
        decode to a point on the curve.

    c.  Reject if A is a small-order point, or if R is a small-order
        point (a point of order 1, 2, 4, or 8).

    d.  Compute k = SHA-512(R || A || M), interpreted as a
        little-endian integer (its reduction modulo L is implicit in
        the scalar multiplication [k]A). Verify the cofactorless group
        equation \[S\]B = R + \[k\]A, where B is the Ed25519 base
        point. Reject if it does not hold. The cofactored equation
        MUST NOT be used in place of the cofactorless equation.

Checks (c) and (d) make AIR signature verification stricter than the
baseline of {{RFC8032}} Section 5.1.7, which permits the cofactored
equation and does not require small-order rejection. The stricter
procedure removes signature malleability the baseline would otherwise
permit.

Step (b) requires only that R and A decode to points on the curve.
AIR v1 does NOT require rejecting a non-canonical point encoding (an
encoded y-coordinate not reduced modulo the field prime); the
mandatory-to-implement Ed25519 verification routines accept such
encodings. Rejecting them is not necessary for AIR security: a
non-canonical re-encoding leaves the receipt's `cti` and claims
unchanged, so it yields no new receipt identity, and the public key A
is obtained out of band from the attestation in canonical form. The
canonical-scalar check in step (a) is required and is distinct from
point-encoding canonicalization.

## Layer 3: Payload Decode and Claim Validation

Layer 3 is the first layer that decodes the payload CBOR, and it is
entered only after the Layer 2 signature check has succeeded.

1.  Decode the payload. Confirm it is a well-formed CBOR map.
    Confirm that every mandatory claim enumerated in the CDDL
    ({{cddl}}) and the EAT Profile Declaration is present; reject the
    receipt if any mandatory claim is absent. The closed-claims-map
    check below rejects unknown keys but does not by itself guarantee
    that the mandatory claims are present.

2.  Confirm `eat_profile` (key 265) equals
    `"https://spec.cyntrisec.com/air/v1"`. Reject receipts with
    unknown profile values.

3.  Confirm `cti` (key 7) is exactly 16 bytes.

4.  Confirm `iat` (key 6) is a non-zero unsigned integer.

5.  Confirm `model_hash` (key -65539) is exactly 32 bytes and not
    all zeros.

6.  Confirm all required text string claims (iss, model_id,
    model_version, policy_version, security_mode) are non-empty and
    within reasonable bounds (implementation-defined, RECOMMENDED
    maximum 1024 bytes each).

7.  Confirm `enclave_measurements` (key -65543) is a map.

8.  Confirm `measurement_type` within enclave_measurements is one
    of the defined values (`"nitro-pcr"` or `"tdx-mrtd-rtmr"`).

9.  Confirm that every measurement value present in the map (whether
    required or optional) is exactly 48 bytes.

10. If `measurement_type` is `"tdx-mrtd-rtmr"`, confirm `pcr8` is
    absent. TDX measurement maps MUST NOT contain `pcr8` (`pcr8`
    is a Nitro-only field).

11. If `model_hash_scheme` (key -65549) is present, confirm it is
    one of the defined values (`"sha256-single"`,
    `"sha256-concat"`, `"sha256-manifest"`). Unknown values MUST be
    rejected.

12. Confirm `security_mode` (key -65548) is one of the defined values
    (`"production"`, `"evaluation"`). Unknown values MUST
    be rejected (fail-closed).

13. Confirm `request_hash` (key -65540), `response_hash` (key
    -65541), and `attestation_doc_hash` (key -65542) are each exactly
    32 bytes, and that `sequence_number` (key -65545),
    `execution_time_ms` (key -65546), and `memory_peak_mb` (key
    -65547) are each unsigned integers.

14. Confirm the claims map contains no unknown integer keys and no
    duplicate keys.

15. If `eat_nonce` (key 10) is present, confirm it is between 8 and 64
    bytes inclusive; reject otherwise ({{RFC9711}} Section 4.1).

## Layer 4: Policy Evaluation

Policy checks are configurable per verifier deployment. The following
checks are defined:

**FRESH** (timestamp bounds):
: If configured, verify `now - max_age <= iat <= now + clock_skew`.

**NONCE** (challenge binding):
: If the verifier supplied a nonce, verify eat_nonce matches.

**MODEL** (expected model):
: If configured, verify model_hash and/or model_id match expected
  values.

**PLATFORM** (expected platform):
: If configured, verify measurement_type matches expected value.

**REPLAY** (deduplication):
: If the verifier maintains a seen-cti store, reject duplicate cti
  values.

Verifiers SHOULD document which Layer 4 policies they enforce.

## Interaction Model Compatibility

AIR is a receipt format; transport and session management are out of
scope (see {{non-goals}}). AIR receipts are compatible with both the
Challenge/Response and Uni-Directional interaction models of
{{I-D.ietf-rats-reference-interaction-models}}:

-   **Challenge/Response**: when the `eat_nonce` claim is present and
    was supplied by the verifier to the workload out of band (for
    example, as an inference-API parameter), the receipt provides
    challenge-response freshness per {{RFC9711}} Section 4.1.
-   **Uni-Directional**: when `eat_nonce` is absent, freshness
    reduces to the `iat` timestamp plus verifier-side `cti`
    deduplication. This is acceptable for deployments that do not
    require challenge-binding, but MUST be understood as weaker than
    challenge-bound freshness: a compromised workload can pre-sign
    receipts, and verifiers relying only on `iat` gain no defense
    beyond clock skew. A validator operating in this mode MUST apply a
    bounded acceptance window (a `max_age` policy) and treat the result
    as recentness, not freshness: it conveys that a receipt is no older
    than the window, not that it was produced in response to a live
    challenge.

Attester-generated nonce values (nonce values not supplied by a
verifier) provide no replay protection and SHOULD NOT be placed in
`eat_nonce`. An implementation that needs a unique per-receipt
identifier for internal purposes should use `cti` or an
application-layer field, not `eat_nonce`.

Deployments that require platform-clock-independent freshness
(for example, where the workload clock is not trusted by the
verifier) may combine AIR with epoch-markers per
{{I-D.ietf-rats-epoch-markers}}. AIR v1 does not itself define an
epoch-marker claim; this integration is out of scope for v1 and may
be considered in a future revision.


# Relationship to Other Work

## draft-messous-eat-ai

{{I-D.messous-eat-ai}} defines AI-related claims for EAT,
including model identification, training metadata, and data-handling policy and SBOM
references. AIR v1 is complementary: where draft-messous-eat-ai focuses
on per-agent identity, provenance, and authorization metadata, AIR v1
focuses narrowly on per-inference execution evidence from a
confidential workload. AIR intentionally binds a specific request/
response event to attestation-linked metadata; it is not a general AI
agent identity profile. A future version of AIR could adopt
registered claim keys from draft-messous-eat-ai once they stabilize,
replacing the current private-use integer keys. The two drafts do not
collide in the private-use key space -- draft-messous-eat-ai uses keys
in the -75000 range while AIR uses -65537 through -65549 -- but a future
coordinated registration SHOULD align them.

## Concurrent AI-Attestation Work

Several concurrent efforts address adjacent parts of the AI-attestation
problem. {{I-D.sharif-ai-model-lifecycle-attestation}} spans the whole
model lifecycle -- from training-data attestation through per-inference
output signing; AIR v1 is narrower, defining only the per-inference
receipt wire format and its verification, and could serve as the
receipt object such a lifecycle framework emits. In the research
literature, AEX (arXiv:2603.14283) attests LLM API request/response
provenance at the API boundary, and "Notarized Agents"
(arXiv:2606.04193) defines receiver-attested receipts for AI agent
actions. AIR's specific contribution is a closed, fail-closed
COSE_Sign1 / CWT / EAT profile for a single confidential inference; it
is not the only or first per-inference evidence scheme, and a future
version could align its claim keys with these efforts.

## SCITT

The Supply Chain Integrity, Transparency and Trust framework
({{RFC9943}}) uses "Receipt" to mean a
Merkle-tree inclusion proof produced by a Transparency Service for a
Signed Statement submitted to it. In AIR, "receipt" means a
workload-signed per-inference evidence object. These are different
artifacts despite the shared word; this document uses "AIR receipt"
throughout to refer to the AIR v1 COSE_Sign1 artifact defined here,
and "SCITT Receipt" when referring to a Transparency-Service
inclusion proof.

AIR receipts are candidate **payloads** for SCITT Signed Statements,
not Signed Statements themselves. A SCITT Signed Statement is a
COSE_Sign1 structure carrying specific CWT claims (issuer, subject,
etc.) that a Transparency Service uses for registration-policy
evaluation. An AIR v1 COSE_Sign1 does not carry those outer
registration-relevant claims. Deployments wishing to anchor AIR
receipts in a SCITT Transparency Service should wrap an AIR COSE_Sign1
as the payload of an outer Signed Statement produced by the issuer,
with the outer envelope supplying the claims required by the
Transparency Service's registration policy.

TEE-backed Transparency Service profiles such as
{{I-D.ietf-scitt-receipts-ccf-profile}} are natural complements to
AIR's TEE-attested workload model. Complementary work by
{{I-D.kamimura-scitt-refusal-events}} covers the refusal-event side
of AI inference auditing, which pairs with AIR's successful-inference
scope to give broader audit coverage.

A SCITT Transparency Service can provide an independent inclusion time
and ordering record for AIR receipts that are submitted to it. It does
not, by itself, prove when the underlying inference ran, and it does
not detect a receipt that the issuer never submitted. Completeness
requires a deployment policy on top of transparency logging, such as
mandatory submission, monotonic counters, per-session manifests, or
client-enforced inclusion proofs.

AIR v1 does not define the outer Signed Statement wrapping or a
registration profile for a SCITT Transparency Service. Future
revisions may define such a profile.

## RATS Architecture

AIR receipts fit the RATS {{RFC9334}} architecture as follows:

- The confidential workload is the **Attester**. AIR receipts are
  Attester-generated claims; they are Evidence in the general sense
  of {{RFC9334}} Section 4.2, specialized to a per-inference
  application scope.
- The **AIR Receipt Validator** (see {{terminology}}) performs
  AIR-local checks (signature, claim structure, local policy). The
  AIR Receipt Validator is not the RATS Verifier of {{RFC9334}}
  Section 4.1; it does not appraise platform Evidence against
  reference values or produce Attestation Results.
- A **RATS Verifier** appraises the platform attestation evidence
  referenced by `attestation_doc_hash` using platform-specific
  procedures and reference values. AIR v1 does not define those
  procedures.
- The end user, auditor, or compliance officer is the **Relying
  Party**. In a deployment that combines AIR with platform attestation,
  the Relying Party consumes both the AIR receipt and any platform
  Attestation Results.
- The TEE hardware vendor (AWS, Intel) is the **Endorser**; their
  attestation infrastructure anchors trust in the platform evidence.

AIR v1 is a workload-emitted artifact, not a Verifier-emitted
Attestation Result. It is therefore distinct from IETF EAR ({{I-D.ietf-rats-ear}}, EAT
Attestation Results), which is produced by a Verifier after evaluating
platform Evidence. In a complete deployment, a Verifier may evaluate
platform Evidence and an AIR receipt together, and an EAR may reference
an AIR receipt as part of the evidence it considered.

This version of AIR assumes a single Attester producing one
attestation document per receipt. Patterns for composite attesters
(multiple sub-attesters in one environment, e.g., CPU TEE + GPU
confidential compute) and multi-verifier orchestration are the
subject of active RATS WG work; see
{{I-D.richardson-rats-composite-attesters}} and
{{I-D.ietf-rats-multi-verifier}}. AIR v1 does not support these
patterns; future versions may define how AIR receipts compose across
such environments.


# Future Profile Candidates {#future-profile-candidates}

AIR v1 defines an intentionally closed claims map with no extension
registry ({{non-goals}}). This section records claim families that
implementation experience and reviewer feedback have identified as
candidates for a FUTURE AIR profile. It defines no new claims and adds
no wire-format requirements; a future revision MAY define some or all
of them, and this document commits to no delivery date. The purpose is
to reserve the design space and to record the trust analysis any such
claims would inherit.

## Decoding and Sampling Parameters

A future profile could carry the decoding configuration of the
inference -- for example temperature, top_p, top_k, a random seed, and
the stop-sequence set. Under the AIR trust model these are
workload-asserted values (Trust Assumption TA-2, {{trust-assumptions}}):
a verifier can policy-pin them -- reject a receipt whose asserted
decoding configuration is not the expected one -- but generally cannot
recompute the response to confirm the configuration was actually
applied, because production inference on hardware accelerators is not
bit-reproducible across runs. Such claims therefore add policy-pinning
value, not independent verifiability, and a profile defining them
SHOULD state this explicitly so that a Relying Party does not read a
pinned decoding claim as proof of the decoding that occurred.

## Structured Context Commitments

AIR v1's `request_hash` commits to the request payload as a single
opaque byte string. A future profile could decompose the context into
separately committed parts -- for example distinct hashes for the user
input, the system prompt, retrieved context (as in retrieval-augmented
generation), and a tool-call / tool-result log -- and could add a
prior-receipt hash to chain multi-step or multi-turn interactions.
These share the decoding parameters' trust class: they are
workload-asserted and corroborable only against artifacts a Relying
Party independently holds. This design space overlaps with the agent
identity and provenance claims of {{I-D.messous-eat-ai}} and with
recent work on attestation and provenance for LLM API
request/response outputs (for example, AEX, arXiv:2603.14283); a future
AIR profile SHOULD reuse registered claim
keys from that work where they exist rather than minting private-use
keys.


# Security Considerations

## Trust Assumptions {#trust-assumptions}

The security properties of AIR verification depend on the following
Trust Assumptions. If any of these assumptions is broken, the
corresponding AIR guarantees are void.

-   **TA-1 (TEE hardware correctness):** the TEE hardware computes
    measurements faithfully, isolates enclave memory from the host
    and hypervisor as specified, and protects the attestation
    signing key. A hardware vulnerability, firmware bug, or supply
    chain compromise affecting the TEE voids all AIR TEE-provenance
    guarantees. AIR v1 does not define revocation mechanisms for
    compromised platforms.

-   **TA-2 (Workload honesty and evidence scope):** the signing
    workload computes the hashes it signs over the data it actually
    processed, and populates claims consistently with the inference
    it actually performed. An AIR receipt only speaks for what the
    signing workload observed and emitted. A malicious or
    misconfigured workload can produce syntactically valid receipts
    that do not correspond to a genuine inference; AIR does not
    protect against such a signer. This assumption is meaningful
    only when combined with TA-3. Moreover, because
    `attestation_doc_hash` MAY reference a reused boot-time attestation
    rather than a per-inference one (see the `attestation_doc_hash`
    claim definition), a valid receipt does not establish that a
    specific inference occurred at a specific time, even when TA-1
    through TA-4 all hold.

-   **TA-3 (Key binding enforced out of band):** for deployments
    asserting end-to-end TEE provenance, the Ed25519 signing key is
    cryptographically bound to the attested workload per
    {{key-binding}}. Without this binding, key substitution attacks
    (see {{key-substitution-attack}}) defeat the TEE-provenance
    claim regardless of TA-1 and TA-2.

-   **TA-4 (Platform attestation verifiable via Endorser trust
    chain):** the attestation document referenced by
    `attestation_doc_hash` can be obtained and validated by a RATS
    Verifier against the platform vendor's trust chain (for
    example, the AWS Nitro root CA, or the Intel DCAP / Provisioning
    Certification Service). AIR v1 does not define these procedures
    and relies on platform-specific verifiers.

AIR-local verification (Layers 1-4 of {{verification-procedure}})
proves only TA-independent properties: receipt well-formedness,
signature validity under a provided public key, claim structural
correctness, and policy match. Claims of TEE provenance require
TA-1 through TA-4 to hold, with TA-3 enforced by the Validator and
TA-4 enforced by a RATS Verifier.

## Receipt Integrity

The Ed25519 signature over the COSE Sig_structure protects the
protected header and all claims against tampering. The unprotected
header is not covered by the signature; AIR v1 requires it to be
empty (Section 4.3).

## Algorithm Pinning

AIR v1 pins the signing algorithm to Ed25519 (alg = -8). The
algorithm identifier is carried in the protected header and is
therefore signed. This prevents algorithm confusion attacks where an
attacker substitutes a weaker algorithm.

As of {{RFC9864}}, the generic EdDSA algorithm identifier -8 is no
longer marked "Recommended" in the IANA COSE Algorithms registry (its
Recommended status is "Deprecated") in favor of algorithm-specific
identifiers. AIR v1 pins -8 for interoperability with currently
deployed COSE tooling; a future AIR profile MAY adopt the
Ed25519-specific algorithm identifier. Algorithm agility in AIR is
handled by profile versioning, not in-band negotiation: a future
revision needing a different or post-quantum signature scheme defines a
new profile identifier (the `eat_profile` value), so a verifier never
has to accept an algorithm the profile did not pin.

## Replay Protection {#replay-protection}

Replay protection in AIR v1 is a shared responsibility:

- The `cti` claim provides a unique receipt identifier. Verifiers
  maintaining state SHOULD track observed cti values and reject
  duplicates.

- The `eat_nonce` claim (optional) provides challenge-response
  freshness. When present, it binds the receipt to a specific
  verifier-supplied challenge, preventing replay to other verifiers.

- The `sequence_number` claim provides monotonicity within an
  observed session. Gaps indicate missing sequence numbers within
  that observed stream; absence of a gap does not prove that every
  receipt was submitted.

Verifiers not maintaining state and not using eat_nonce have limited
replay protection (only iat-based freshness). Deployments requiring
strong replay resistance MUST use at least one of cti deduplication
or eat_nonce. A verifier configured with neither cti deduplication nor
eat_nonce checking SHOULD surface a warning that the receipt has no
replay protection beyond iat-based freshness.

### Freshness Boundary

The freshness an AIR receipt conveys is bounded by who holds the
nonce. `eat_nonce` demonstrates freshness only to the party that
issued the nonce; a later auditor who did not issue or observe that
nonce cannot infer freshness from it. The `iat` claim is a
workload-asserted time -- useful for verifier policy such as an age
bound, but not an externally attested timestamp, and a compromised
workload can assert any value.

An AIR receipt therefore does not, on its own, give an after-the-fact
auditor verifiable freshness, nor evidence that the set of receipts is
complete. Audit-time freshness and non-omission require an external
mechanism -- for example, a transparency log that countersigns
receipts with an independent timestamp, or an external sequencing
authority -- layered on AIR. AIR v1 does not define that layer.

## Model Hash Limitations

The `model_hash` claim proves byte-level identity for the model
artifact set as defined by `model_hash_scheme`, not model correctness,
bias, or safety. Two distinct artifact sets with identical hashes are
computationally infeasible, but a model with a correct hash may still
produce harmful or incorrect outputs.

`model_hash` identifies the serialized model artifact set, not the
in-memory computational form actually executed. Quantization, kernel
fusion, speculative decoding, and other runtime optimizations can make
the executing model differ numerically from the hashed artifacts;
`model_hash` binds which artifacts were referenced, not the exact
computation performed.

The `model_hash_scheme` claim ({{mhscheme}}) declares how the hash
was computed. Unknown scheme values MUST be rejected. This prevents
a verifier from accepting a hash computed with an unrecognized method
that might weaken integrity guarantees.

The `model_hash` claim is application-layer evidence. By itself it
does not prove that the corresponding artifacts were loaded or
executed inside a hardware-attested environment; that requires
verification of the attested workload and its model-loading path.

## Attestation Document Not Verified by Receipt

The `attestation_doc_hash` claim is a SHA-256 hash of the platform
attestation document. AIR v1 does not embed or verify the attestation
document. AIR-local verification alone is therefore insufficient to
establish TEE assurance. Verifiers requiring such assurance MUST
independently obtain and verify the attestation document using
platform-specific procedures (e.g., Nitro COSE verification against
the AWS root CA, Intel TDX DCAP verification against Intel PCS).

## Accelerator Attestation Scope {#accelerator-scope}

An AIR v1 receipt attests the CPU-side TEE only. On a platform that
also provides accelerator (for example, GPU) confidential computing,
the accelerator's confidential-computing mode, device identity, and
memory-protection state are NOT covered by the receipt, and are not
implied by a successful `enclave_measurements` reconciliation. A
Relying Party MUST NOT infer accelerator confidentiality from an AIR v1
receipt, and a party presenting such a receipt MUST NOT represent it as
covering accelerator confidentiality. Where accelerator confidentiality
is part of the trust decision, it MUST be established out of band from
device-side Evidence (see the composite-attester note in {{non-goals}})
and MUST NOT be assumed from the presence of an AIR receipt. A future
composite-attester AIR profile may bind CPU-side and accelerator-side
Evidence into a single verifiable object.

## Workload Honesty and Evidence Scope

An AIR receipt only speaks for what the signing workload observed and
emitted. If the workload is malicious, misconfigured, or signs hashes
for data that did not come from the claimed inference path, AIR can
still produce a syntactically valid receipt. AIR therefore does not
protect against an untrusted signer or against semantics outside the
measured workload boundary.

Deployments that rely on AIR for end-to-end assurance MUST treat the
receipt as meaningful only when the signing key is bound to an
attested workload whose measurement set and execution policy are
acceptable to the verifier.

## Claim Trust Classes {#claim-trust-classes}

Every claim in an AIR receipt is covered by the receipt signature, but
that signature proves only that the *workload* asserted the claim. It
does not, on its own, make the claim true. Claims differ in whether,
and how, a verifier or Relying Party can corroborate them against
evidence outside the receipt. This section classifies every AIR v1
claim so that implementers and Relying Parties do not mistake a
workload self-assertion for independently established fact.

In RATS terms ({{RFC9334}}), a claim is corroborated hardware Evidence
only when an Attesting Environment measured it and a Verifier appraises
it against reference values; the remaining claims are workload
assertions that the receipt signature authenticates but does not make
true. Three trust classes are used:

-   **Self-asserted:** backed only by the workload's signature. A
    malicious or misconfigured workload can place any syntactically
    valid value in the claim; the receipt signature does not elevate
    such a claim beyond "the workload stated this."
-   **Externally corroborable:** a Relying Party that independently
    holds the corresponding artifact (a known-good reference value,
    the request or response bytes, or a verifier-supplied nonce) can
    confirm the claim by recomputation or comparison.
-   **Attestation-corroborable:** the claim is meaningful only after a
    verifier obtains and validates the platform attestation document
    and reconciles the claim against it per {{validator-behavior}}.
    Before that reconciliation the claim is self-asserted.

| Claim | Trust class | Corroboration available to a Relying Party |
|-------|-------------|---------------------------------------------|
| `iss` | Self-asserted | None; MAY be checked against an issuer allowlist |
| `iat` | Self-asserted | None; workload clock (see {{replay-protection}} and Clock Integrity) |
| `cti` | Self-asserted | None; uniqueness is assumed, not proven |
| `eat_profile` | Self-asserted (fixed constant) | Verifier checks the exact AIR v1 profile URI |
| `eat_nonce` | Externally corroborable | Only by the verifier that supplied the nonce |
| `model_id` | Self-asserted | None; operator-assigned opaque string |
| `model_version` | Self-asserted | None; operator-assigned opaque string |
| `model_hash` | Externally corroborable | Compare against a known-good reference hash |
| `request_hash` | Externally corroborable | Recompute from the request bytes the Relying Party holds |
| `response_hash` | Externally corroborable | Recompute from the response bytes the Relying Party holds |
| `attestation_doc_hash` | Attestation-corroborable | Re-hash the independently obtained attestation document. For a TEE-provenance receipt this is the same document that carries the key binding and reconciled measurements; it is typically boot-time, so it shows execution *in* the attested workload, not *at the time of* this inference (see the `attestation_doc_hash` claim definition). |
| `enclave_measurements` | Attestation-corroborable | Reconcile against the validated attestation document per {{validator-behavior}}; self-asserted until then |
| `policy_version` | Self-asserted | None; operator-assigned |
| `sequence_number` | Self-asserted | None; informational only (see its claim definition) |
| `execution_time_ms` | Self-asserted | None; informational |
| `memory_peak_mb` | Self-asserted | None; informational |
| `security_mode` | Self-asserted | None; does not substitute for attestation-based trust |
| `model_hash_scheme` | Self-asserted | Structural; declares how `model_hash` was computed |

The `enclave_measurements` claim warrants specific attention. It
carries platform measurement registers (PCR or MRTD/RTMR values) and
therefore resembles hardware-rooted evidence, but within the receipt
it is a Self-asserted claim: the values are written and signed by the
workload, not by the platform attestation service. It becomes
corroborated platform evidence only after the {{validator-behavior}}
reconciliation against the validated attestation document. A verifier
that presents `enclave_measurements` to a Relying Party as a verified
measurement, without performing that reconciliation, misrepresents a
workload self-assertion as hardware evidence.

## Key Substitution Attack {#key-substitution-attack}

If an implementation does not enforce key binding as described in
{{key-binding}}, a workload compromise enables a key-substitution
attack. An attacker with code execution in the workload may:

1.  Extract the Ed25519 signing private key.
2.  Obtain or generate a fresh platform attestation document with a
    different REPORTDATA (or equivalent field), which may correspond
    to a different measurement or a different workload image.
3.  Sign AIR receipts with the extracted key and populate
    `attestation_doc_hash` with the hash of the new attestation
    document.

A verifier that checks only the AIR signature and the
`attestation_doc_hash` field cannot distinguish such receipts from
receipts produced by the attested workload. AIR-local verification
remains valid in the narrow sense that the signature and claim
structure are well-formed, but end-to-end TEE provenance is broken.

Deployments that claim end-to-end TEE provenance from AIR receipts
MUST therefore enforce key binding per {{key-binding}}, and verifiers
enforcing such claims MUST check that binding using platform-specific
procedures.

## Signing Key Reuse

{{key-binding}} requires the attested AIR signing key to be
single-purpose. Ed25519 unforgeability is analyzed for a key used in a
single signing role; reusing the attested key across protocols falls
outside that model and can enable cross-protocol signature confusion,
in which a signature produced for another protocol is presented as an
AIR receipt, or an AIR receipt signature is replayed into another
protocol.

## TEE Compromise

See TA-1 in {{trust-assumptions}}. Operators of verifiers SHOULD
consult platform-vendor advisories and maintain an allowlist or
denylist of accepted platform measurements and TCB versions to
respond to disclosed hardware or firmware vulnerabilities. AIR v1
does not itself define revocation or TCB-rollback signaling; this is
typically performed by the platform-specific RATS Verifier against
its reference-value store.

## Clock Integrity

The `iat` claim depends on the workload's system clock. On AWS
Nitro, the enclave uses the host clock (no independent time source).
On Intel TDX, the CVM has a TSC but it is subject to frequency
scaling. AIR v1 freshness checks are only as accurate as the
platform clock.

## Deterministic Encoding

AIR v1 requires deterministic CBOR encoding ({{RFC8949}} Section
4.2.1). This ensures that the same claims always produce the same
payload bytes, preventing signature-valid variants of the same
receipt. Implementations MUST sort map keys per the CBOR
deterministic encoding rules.

## Closed Claims Map

The claims map is closed: unknown integer keys MUST be rejected.
This prevents downgrade attacks where an attacker adds unrecognized
claims that a naive verifier might silently accept as benign. This
closed-scope behavior is intentional in AIR v1; future extensions
require a revised profile.


# Privacy Considerations

## Input/Output Hashes

The request_hash and response_hash claims contain SHA-256 hashes,
not plaintext inputs or outputs. However, for low-entropy inputs
(e.g., binary classification queries, yes/no questions), an
adversary with knowledge of the input space could brute-force the
hash to recover the original input. Deployments handling sensitive
low-entropy data SHOULD consider whether receipt exposure risks
input recovery.

A deployment MAY mitigate this by folding a per-receipt secret salt
(for example, the `eat_nonce`, or a random value retained by the
issuer) into the hashed preimage, so that `request_hash` and
`response_hash` are not dictionary-confirmable by an observer who does
not hold the salt. This is a deliberate trade-off: a salted hash is no
longer independently recomputable by a Relying Party that holds only
the request or response bytes, so the claim's trust class shifts from
externally-corroborable to corroborable-only-with-the-salt (see
{{claim-trust-classes}}). A profile that defines salting MUST specify
how the salt is conveyed to authorized verifiers.

## Correlation Metadata

AIR receipts contain timestamps (iat), sequence numbers, and
identifiers (cti, iss) that could be used to correlate activity
across receipts. In privacy-sensitive deployments, operators SHOULD
consider whether the combination of receipt metadata enables
unwanted profiling.

## Nonce Privacy

The eat_nonce claim, when present, may leak correlation data if the
same nonce is reused across sessions or if the nonce encodes
client-identifying information. Verifiers SHOULD use random nonces
and avoid embedding client identifiers in nonce values.

## Issuer Identity

The `iss` claim identifies the emitting entity. If the deployment
assigns `iss` a human-readable value such as an organization name,
the resulting receipts disclose the issuer's identity to anyone who
can read them. For receipts that flow to auditors or relying parties
outside the trust boundary of the issuer, this is usually intended
and acceptable. For receipts that may be shared further (for
example, aggregated in a transparency log, forwarded to external
regulators, or included in public audit artifacts), the human-readable
issuer identity may exceed the intended disclosure scope.

Deployments requiring issuer pseudonymity SHOULD use opaque `iss`
values (for example, UUIDs or randomly-generated identifiers) and
distribute issuer mappings out of band to the parties that need
them.

## Signing Key and Identifier Linkability

The Ed25519 receipt signing key is, in effect, a persistent pseudonym:
every receipt a given attested workload emits is signed by the same
key, so an observer can link all of that workload's inferences to one
another and, via the key binding, to one attested environment. The
`model_id` and `enclave_measurements` claims are likewise stable
cross-receipt correlators. Where unlinkability across receipts or
across relying parties matters, a deployment SHOULD use
per-relying-party or rotating signing keys, each separately attested,
accepting the additional attestation cost. AIR v1 does not use the EAT
`ueid`, `sueids`, `oemid`, `hwmodel`, or `hwversion` claims -- the
closed claims map prohibits them -- which avoids the permanent-
hardware-identifier linkability discussed in {{RFC9711}} Section 8. The
`cti` claim SHOULD be a random 128-bit value rather than a counter (see
its claim definition); `sequence_number` is a deliberately
session-linkable field, and because it is informational only a
deployment concerned with linkability MAY emit a constant value for it.


# IANA Considerations

This document has no IANA actions at this time.

AIR v1 uses negative integer keys in the CWT private-use range
(keys -65537 through -65549). If AIR gains adoption, a future
version may request registration of these claims in the CWT Claims
registry established by {{RFC8392}}. The eat_profile URI
(`"https://spec.cyntrisec.com/air/v1"`) follows the EAT profile
naming conventions in {{RFC9711}} but is not registered in any
IANA registry.

The HTTP media type `application/eat+cwt` referenced in Section 6
is registered by {{RFC9782}}.


# Implementation Status

Note to RFC Editor: Please remove this section before publication.

This section records the status of known implementations of the
protocol defined by this specification at the time of posting, per
{{RFC7942}}.

## Reference Implementation (Rust)

Organization:
: Cyntrisec

Implementation:
: EphemeralML (`common/src/air_receipt.rs`, `common/src/air_verify.rs`)

Description:
: Full AIR v1 emitter and 4-layer verifier. Generates COSE_Sign1
  receipts with deterministic CBOR encoding and Ed25519 signing.
  Verifier implements all four layers (parse, crypto, claims, policy)
  with structured error codes.

Maturity:
: Demonstration. The implementation emits AIR v1 receipts and performs
  AIR-local verification on the Nitro, TDX, and GCP Confidential Space
  paths. Enforced single-document AIR TEE provenance per
  {{validator-behavior}} is implemented for Nitro: the AIR signing key is
  extracted from the AWS-signed NSM attestation document referenced by
  `attestation_doc_hash`, and the client reconciles and appraises that
  document's measurement registers against caller-supplied reference
  values before asserting provenance. On TDX and GCP Confidential Space
  today, the receipt's `attestation_doc_hash` references a boot-time
  quote, while the receipt-signing-key binding and DCAP/platform
  verification are carried through a separate transport attestation and
  platform-evidence bundle. That is exactly the split model
  {{validator-behavior}} places out of scope for AIR v1 TEE provenance,
  so those receipts are treated as AIR-local. Binding the
  receipt-signing key into the `attestation_doc_hash` quote and a
  TDX/GCP AIR chained verifier that validates that quote and appraises
  its MRTD/RTMR registers against reference values are future work.

Coverage:
: The reference implementation passes its test suite, including the
  AIR v1 golden conformance vectors ({{appendix-vectors}}).

Contact:
: borys@cyntrisec.com

## Python Interop Verifier

Organization:
: Cyntrisec (same team, independent implementation)

Implementation:
: `spec/v1/scripts/interop_test.py`

Description:
: Minimal Python verifier using `pycose` and `cbor2` libraries.
  Validates COSE_Sign1 structure, Ed25519 signature, and claim
  presence.

Maturity:
: Test/interop.

## Client Nonce Conveyance

The reference gateway accepts an optional client-supplied challenge
nonce on its OpenAI-compatible HTTP endpoints via a request header,
`X-Cyntrisec-Air-Nonce` (a hex string). When the header is present and
within the RFC 9711 length bounds, the gateway conveys the nonce to
the workload, which binds it into the receipt's `eat_nonce` claim.

This header is an implementation convention of the reference gateway
only. It is not part of the AIR receipt format, is not required for
conformance, and a different deployment may convey the nonce by any
means. AIR v1 defines the `eat_nonce` claim; it does not define how a
nonce reaches the workload.

## E2E Validation

The reference implementation has been exercised on three confidential
computing platforms. "PASS" below means AIR receipt emission plus
AIR-local verification plus measurement hardware-rootedness. Nitro
additionally exercises the enforced single-document AIR TEE-provenance
path of {{validator-behavior}}. On TDX and GCP Confidential Space the
evidence is currently split between the boot-time `attestation_doc_hash`
quote and the separate transport / platform-evidence verifier; full
single-document Validator Behavior on those platforms is future work
(see Maturity above):

| Platform                  | Status | Date       | Notes |
|:--------------------------|:-------|:-----------|:------|
| AWS Nitro Enclaves (m6i)  | PASS   | 2026-02-28 | Nitro PCR measurements carried in the receipt. |
| GCP Confidential Space TDX (c3-standard-4) | PASS | 2026-02-27 | TDX MRTD/RTMR0/RTMR1 carried in the receipt. |
| GCP Confidential Space GPU H100 CC (a3-highgpu-1g) | PASS | 2026-02-27 | AIR v1 receipt emitted on a platform that also provides NVIDIA GPU confidential compute. The receipt carries only the CPU-side (TDX) attestation per AIR v1 scope; GPU attestation is verified out of band and is not embedded in the receipt. |


# Examples

## Valid Receipt Walkthrough

The following describes a valid AIR v1 receipt in diagnostic
notation. This corresponds to the `v1-nitro-no-nonce` golden vector.

The COSE_Sign1 envelope (tagged with CBOR tag 18):

~~~
18([
  h'A2012703183D',           / protected: {1: -8, 3: 61} /
  {},                         / unprotected: empty /
  h'B0...',                   / payload: CWT claims map /
  h'<64 bytes>'               / signature: Ed25519 /
])
~~~

The protected header decodes to:

~~~
{
  1: -8,    / alg: EdDSA /
  3: 61     / content type: application/cwt /
}
~~~

The payload (CWT claims map) includes 16 required claims, including the
EAT profile:

~~~
{
  1: "cyntrisec.com",                          / iss /
  6: 1740000000,                               / iat /
  7: h'<16 bytes UUID v4>',                    / cti /
  265: "https://spec.cyntrisec.com/air/v1",    / eat_profile /
  -65537: "minilm-l6-v2",                      / model_id /
  -65538: "1.0.0",                             / model_version /
  -65539: h'<32 bytes SHA-256>',               / model_hash /
  -65540: h'<32 bytes SHA-256>',               / request_hash /
  -65541: h'<32 bytes SHA-256>',               / response_hash /
  -65542: h'<32 bytes SHA-256>',               / attestation_doc_hash /
  -65543: {                                    / enclave_measurements /
    "pcr0": h'<48 bytes SHA-384>',
    "pcr1": h'<48 bytes SHA-384>',
    "pcr2": h'<48 bytes SHA-384>',
    "measurement_type": "nitro-pcr"
  },
  -65544: "policy-2026.02",                    / policy_version /
  -65545: 1,                                   / sequence_number /
  -65546: 77,                                  / execution_time_ms /
  -65547: 0,                                   / memory_peak_mb /
  -65548: "production"                         / security_mode /
}
~~~

Verification with the corresponding Ed25519 public key succeeds
through all four layers.

## Invalid Receipt Categories

The specification includes invalid golden vectors covering failure
modes across all verification layers. The structural and policy
vectors are:

| Vector               | Layer | Expected Failure         |
|:---------------------|:------|:-------------------------|
| wrong-key            | L2    | SIG_FAILED               |
| wrong-alg            | L1    | BAD_ALG                  |
| zero-model-hash      | L3    | ZERO_MODEL_HASH          |
| bad-measurement-length | L3  | BAD_MEASUREMENT_LENGTH   |
| nonce-mismatch       | L4    | NONCE_MISMATCH           |
| model-hash-mismatch  | L4    | MODEL_HASH_MISMATCH      |
| platform-mismatch    | L4    | PLATFORM_MISMATCH        |
| stale-iat            | L4    | TIMESTAMP_STALE          |

The signature-strictness vectors exercise the strict Ed25519
verification algorithm of {{verification-procedure}} Layer 2. Each is a
valid receipt body whose 64-octet signature violates one Layer 2 check
(the letters reference the checks enumerated in that section):

| Vector              | Layer | Expected Failure | Check |
|:--------------------|:------|:-----------------|:------|
| sig-s-out-of-range  | L2    | SIG_FAILED       | (a)   |
| sig-small-order-r   | L2    | SIG_FAILED       | (c)   |
| sig-small-order-a   | L2    | SIG_FAILED       | (c)   |
| sig-cofactored-only | L2    | SIG_FAILED       | (d)   |

Complete vector files (JSON with hex-encoded COSE bytes, expected
failure codes, and policy overrides) are available in the reference
implementation repository.


--- back

# Full CDDL Schema {#appendix-cddl}

This appendix reproduces the complete CDDL schema from {{cddl}} for
convenience.

~~~ cddl
; Attested Inference Receipt (AIR) v1 -- CDDL Schema
; Status: v1.0 -- closed claim set, single-inference scope
; References: RFC 9052, RFC 8392, RFC 9711, RFC 8949, RFC 8610

air-receipt = #6.18([
  protected:   bstr .cbor air-protected-header,
  unprotected: air-unprotected-header,
  payload:     bstr .cbor air-claims,
  signature:   bstr .size 64
])

air-protected-header = {
  1 => -8,          ; alg: EdDSA (Ed25519)
  3 => 61,          ; content type: application/cwt
}

air-unprotected-header = {}

air-claims = {
  ; --- Standard CWT/EAT claims ---
  1   => tstr,                  ; iss: issuer
  6   => uint,                  ; iat: issued-at (Unix seconds)
  7   => bstr .size 16,         ; cti: CWT ID (UUID v4, 16 bytes)
  265 => "https://spec.cyntrisec.com/air/v1",  ; eat_profile
  ? 10 => bstr .size (8..64),   ; eat_nonce (optional)

  ; --- AIR private claims ---
  -65537 => tstr,               ; model_id
  -65538 => tstr,               ; model_version
  -65539 => sha256-hash,        ; model_hash
  -65540 => sha256-hash,        ; request_hash
  -65541 => sha256-hash,        ; response_hash
  -65542 => sha256-hash,        ; attestation_doc_hash
  -65543 => enclave-measurements, ; enclave_measurements
  -65544 => tstr,               ; policy_version
  -65545 => uint,               ; sequence_number
  -65546 => uint,               ; execution_time_ms
  -65547 => uint,               ; memory_peak_mb
  -65548 => tstr,               ; security_mode

  ; --- Optional claims (v1.0) ---
  ? -65549 => tstr,             ; model_hash_scheme
}

sha256-hash = bstr .size 32
sha384-hash = bstr .size 48

enclave-measurements = nitro-measurements / tdx-measurements

nitro-measurements = {
  "pcr0"             => sha384-hash,   ; image
  "pcr1"             => sha384-hash,   ; kernel + ramdisk
  "pcr2"             => sha384-hash,   ; application
  ? "pcr3"           => sha384-hash,   ; IAM role (optional)
  ? "pcr4"           => sha384-hash,   ; instance identity (optional)
  ? "pcr8"           => sha384-hash,   ; signing cert (optional)
  "measurement_type" => "nitro-pcr",
}

tdx-measurements = {
  "pcr0"             => sha384-hash,   ; MRTD
  "pcr1"             => sha384-hash,   ; RTMR0
  "pcr2"             => sha384-hash,   ; RTMR1
  ? "pcr3"           => sha384-hash,   ; RTMR2 (optional)
  ? "pcr4"           => sha384-hash,   ; RTMR3 (optional)
  "measurement_type" => "tdx-mrtd-rtmr",
}
~~~


# Golden Vector Summary {#appendix-vectors}

The reference implementation includes 19 golden test vectors (2 valid,
17 invalid) generated with a deterministic Ed25519 key pair:

- Seed: `2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a`
- Public key: `197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61`

Vectors are JSON files containing the COSE_Sign1 bytes (hex-encoded),
expected verification outcomes, and policy overrides for Layer 4
tests. They are available in the repository under `spec/v1/vectors/`.

Valid vectors:

-   `v1-nitro-no-nonce.json`: Nitro measurements, no eat_nonce
    (canonical golden vector).

-   `v1-tdx-with-nonce.json`: TDX measurements, with eat_nonce
    (tests nonce binding and TDX measurement variant).

Invalid vectors exercise specific failure modes across all four
verification layers. The following are a representative subset; the
complete set (including the signature-strictness, trailing-byte, and
duplicate-key vectors) is in the repository under `spec/v1/vectors/`:

-   `v1-wrong-key.json` (L2: SIG_FAILED)
-   `v1-wrong-alg.json` (L1: BAD_ALG)
-   `v1-zero-model-hash.json` (L3: ZERO_MODEL_HASH)
-   `v1-bad-measurement-length.json` (L3: BAD_MEASUREMENT_LENGTH)
-   `v1-nonce-mismatch.json` (L4: NONCE_MISMATCH)
-   `v1-model-hash-mismatch.json` (L4: MODEL_HASH_MISMATCH)
-   `v1-platform-mismatch.json` (L4: PLATFORM_MISMATCH)
-   `v1-stale-iat.json` (L4: TIMESTAMP_STALE)


# Acknowledgments
{:numbered="false"}

The author thanks the RATS working group for the foundational
architecture ({{RFC9334}}), the EAT editors for the profiling
framework ({{RFC9711}}), and the COSE editors for the signing
structures ({{RFC9052}}). The measurement of confidential computing
overhead referenced in this document was performed on AWS Nitro
Enclaves and GCP Confidential Space (Intel TDX).
