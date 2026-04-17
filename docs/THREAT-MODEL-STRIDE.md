# EphemeralML STRIDE Threat Model

- **Version:** 0.2 (draft, post-review 1)
- **Date:** 2026-04-13
- **Scope:** End-to-end EphemeralML inference workload — client, enclave, KMS, model storage, receipt chain
- **Audience:** Security reviewers, pilot partners' security teams, compliance auditors, internal developers
- **Status:** Draft for review — not yet covered by formal legal / compliance sign-off

## Relation to other documents

This document complements existing artifacts; it does not supersede them:

| Related doc | What it covers | This doc adds |
|---|---|---|
| `spec/v1/threat-model.md` | AIR v1 receipt format threat model (RATS roles, attestation-token threats) | End-to-end system view, STRIDE decomposition, application-level threats |
| `docs/SECURITY_MODEL.md` | Trust assumptions (what we trust / reduce trust in) | Explicit STRIDE enumeration, per-data-flow threats, residual risk matrix |
| `SECURITY.md` | Vulnerability disclosure process | — |
| `compliance/` crate | HIPAA/SOC 2 control mapping (planned) | Threat-to-control linkage (future work) |
| `startup-plans/09-compliance/claim-language-guardrails.md` | Marketing / customer-facing wording rules | This doc follows those rules; see claim-safety notes inline |

## 1. System overview

### 1.1 High-level architecture

```
                           Public internet
   ┌───────────┐   TLS    ┌──────────────────────────────────┐
   │  Client   │─────────▶│  gateway-api (public endpoint)   │
   │  (tenant) │          └────────────────┬─────────────────┘
   └─────┬─────┘                           │
         │ verifies                        │ forwarded via
         │ AIR v1 receipt                  │ confidential-ml-transport
         │                                 │ (attested, end-to-end encrypted)
         │                                 ▼
         │                  ┌──────────────────────────────────────┐
         │                  │  Attested Enclave (TEE)               │
         │                  │  ┌────────────────────────────────┐   │
         │                  │  │ enclave: model inference        │   │
         │                  │  │ receipt generator + Ed25519 key │   │
         │                  │  │ session AEAD (ChaCha20-Poly1305)│   │
         │                  │  └────────────────────────────────┘   │
         │                  │  Hardware: SEV-SNP / TDX / Nitro      │
         │                  └─────┬──────────────────┬──────────────┘
         │                        │                  │
         │                        │ GETs             │ attestation-gated
         │                        │ encrypted blob   │ KEK release
         │                        ▼                  ▼
         │                  ┌──────────┐       ┌──────────────┐
         │                  │  Model   │       │  KMS         │
         │                  │  Storage │       │  (attested-  │
         │                  │  (GCS/S3)│       │   only key   │
         │                  └──────────┘       │   release)   │
         │                                     └──────────────┘
         │
         ▼
  ┌──────────────────────┐
  │  Verifier (CLI or    │
  │  hosted API, future) │
  │  Checks receipt +    │
  │  attestation chain   │
  └──────────────────────┘
```

### 1.2 Trust boundaries

| # | Boundary | Enforcement mechanism |
|---|---|---|
| TB-1 | Client machine ↔ public internet | TLS to gateway; TLS is terminated at gateway, re-established inside the attested handshake |
| TB-2 | Gateway ↔ Enclave | `confidential-ml-transport` 3-message mutual handshake with attestation-bound session keys |
| TB-3 | Enclave memory ↔ Host OS / hypervisor | Hardware TEE memory isolation (SEV-SNP / TDX / Nitro Enclaves) |
| TB-4a (GCP) | Enclave ↔ Google Cloud KMS | HTTPS; WIF token exchange from Cloud Attestation OIDC → WIP-bound DEK release. KMS policy pins image digest + TDX measurements before release. |
| TB-4b (AWS) | Enclave ↔ AWS KMS (via host KMS proxy) | NSM-signed attestation document → AWS KMS `Decrypt` with `RecipientInfo`. KMS verifies PCRs against key policy and returns the DEK wrapped to an RSA-2048 ephemeral key embedded in the attestation. Host-side proxy relays the ciphertext only. |
| TB-4c (Azure) | Enclave ↔ Azure Key Vault (planned) | Azure Attestation → AAD token → AKV `release_key`. Full app-layer flow not yet validated end-to-end; transport layer validated 2026-03-15. |
| TB-5 | Enclave ↔ Model Storage | HTTPS + IAM + storage-side encryption at rest; DEK acquired via TB-4a/4b/4c per deployment |
| TB-6 | Client ↔ Verifier (future hosted API) | TLS; verifier never receives plaintext request/response — only hashes from receipt |

### 1.3 Deployment modes

This threat model applies to multi-cloud deployments. Not all mitigations are equally strong in every mode — per §6 residual risks.

| Mode | Status | TEE technology |
|---|---|---|
| GCP Confidential Space (TDX) | **E2E validated** (2026-02-27 evidence) | Intel TDX + Google-maintained CS image + Cloud KMS WIP |
| GCP H100 Confidential Computing | **E2E validated** (2026-02-27 evidence) | Intel TDX host + NVIDIA H100 CC + Google Cloud Attestation |
| AWS Nitro Enclaves | **E2E validated** (2026-02-27 evidence) | AWS Nitro Enclaves, NSM-signed attestation docs |
| Azure SEV-SNP (CPU) | **transport-level pass** (2026-03-15 evidence); full app E2E planned | AMD SEV-SNP + Azure vTPM + HCL report |

## 2. Assets

### 2.1 Primary assets (what attackers want)

| Asset ID | Asset | Sensitivity |
|---|---|---|
| A-01 | Tenant's input prompt / data | Highest — often PHI (healthcare), NPI (finance), privileged (legal) |
| A-02 | Inference output / response | Highest — derived from A-01, equally sensitive |
| A-03 | Model weights | High — vendor IP; depending on contract may be confidential or open |
| A-04 | AIR v1 receipt contents | Medium — signed audit artifact; contents are hashes (not plaintext) but reveal session metadata |
| A-05 | AIR v1 receipt signing key (Ed25519 private) | Highest — compromise lets attacker forge receipts with valid signatures |
| A-06 | Session HPKE + AEAD keys | Highest per session; ephemeral |
| A-07 | Attestation document (chip-signed) | Medium — public-observable but tampering detection is the whole point |
| A-08 | KMS-released data-encryption key | Highest — lives briefly in enclave, decrypts A-03 |

### 2.2 Secondary assets (infrastructure)

| Asset ID | Asset | Sensitivity |
|---|---|---|
| A-09 | Attestation collateral (VCEK, PCK chain, Cloud Attestation token) | Medium; tampering detected by chain verification |
| A-10 | Model manifest (SHA-256 + Ed25519 signature by model publisher) | Medium |
| A-11 | Audit logs (structured tracing output) | Low — redacted; no plaintext |
| A-12 | Telemetry (handshake latency, bench results) | Low |

## 3. Threat actors

| ID | Actor | Capabilities (in scope) |
|---|---|---|
| TA-1 | Passive network attacker | Eavesdrop TLS / transport traffic |
| TA-2 | Active network attacker (MITM) | Inject, modify, drop traffic; serve forged certs |
| TA-3 | Cloud operator (legitimate) | Sees control-plane metadata, billing, can terminate VMs. **Cannot access TEE memory.** |
| TA-4 | Malicious hypervisor / compromised host OS | Hypervisor on the physical host. Within the Confidential Computing threat model — blocked from reading VM memory by hardware. **May** attempt side channels. |
| TA-5 | Rogue insider at EphemeralML operator | Access to deployment pipelines; can push image updates unless gated |
| TA-6 | Compromised client machine | Legitimate tenant's laptop is malware-infected |
| TA-7 | Rogue insider at the model-provider org | Can poison model weights before publication |
| TA-8 | Compromised TEE hardware (known CVE) | BadRAM (CVE-2024-56161), CacheWarp, Heckler, SGAxe-class. Breaks some assumptions. |
| TA-9 | Peer tenant on same physical host | Side-channel attacker (cache, microarchitecture) |
| TA-10 | Nation-state with hardware exfiltration | Out of scope — see §6 residual risks |

### 3.1 Explicitly out of scope

- **Compromise of TEE vendor root keys.** AMD's ARK, Intel's SGX root, AWS Nitro signing CA. If these are compromised, entire chains of trust collapse. We trust the vendor root at the level RFC 9334 describes.
- **Physical access to the cloud data center.** If TA-10 extracts keys via physical attack on a CPU, downstream protocol-level mitigations do not apply.
- **Attacks on the tenant's laptop that exfiltrate the tenant's private data before it ever enters the service.** Out of our control; downstream of TA-6.
- **Denial of service at the infrastructure level** (BGP, DNS, DDoS against cloud providers). Partially covered by gateway rate-limiting (Phase 1 transport hardening) but cloud-layer DDoS is the provider's responsibility.

## 4. Data flows

| DF | From → To | Channel | Primary data | Crosses boundary |
|---|---|---|---|---|
| DF-1 | Client → gateway | HTTPS (TLS 1.3) | Request envelope | TB-1 |
| DF-2 | gateway → Enclave | `confidential-ml-transport` handshake + encrypted frames | Request payload + nonce + pubkey | TB-2 |
| DF-3 (GCP) | Enclave → Google Cloud Attestation | HTTPS | TDX quote → OIDC token | Within cloud provider |
| DF-3 (AWS) | Enclave → NSM (in-enclave device) | ioctl | Request → signed attestation document (COSE_Sign1) | — (internal to enclave + NSM) |
| DF-4 (GCP) | Enclave → Cloud KMS | HTTPS + WIF token | Decrypt request with attested identity | TB-4a |
| DF-4 (AWS) | Enclave → KMS proxy on host → AWS KMS | vsock / HTTPS | `Decrypt` with `RecipientInfo` (attestation doc + RSA pubkey) | TB-4b |
| DF-5 (GCP) | Cloud KMS → Enclave | HTTPS | Unwrapped DEK (TLS only) | TB-4a |
| DF-5 (AWS) | AWS KMS → host → Enclave | HTTPS / vsock | DEK wrapped to enclave's RSA-2048 ephemeral key; unwrapped in-enclave | TB-4b |
| DF-6 | Enclave → Model Storage | HTTPS + IAM | GET encrypted model blob | TB-5 |
| DF-7 | Enclave → Enclave (inference) | in-process | Plaintext input → model → plaintext output | — (internal to TEE) |
| DF-8 | Enclave → Client | `confidential-ml-transport` encrypted frame | Response + AIR v1 receipt | TB-2, TB-1 |
| DF-9 | Client → Verifier (CLI or hosted) | out-of-band / TLS | Receipt + attestation artifacts | TB-6 |

## 5. STRIDE analysis

Each row: **(Asset or DF) × STRIDE category × Specific threat × Mitigation × Status**.

### 5.1 Per-asset STRIDE

| ID | Asset | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|---|
| T-01 | A-01 input | **S**poofing | Attacker impersonates a legitimate tenant, sends request as if from another | Gateway supports a single optional shared bearer token (`EPHEMERALML_API_KEY`, see `gateway-api/src/auth.rs`), compared in constant time. This is **not** per-tenant auth — all holders of the shared token are indistinguishable to the gateway. Per-tenant identity must be enforced by an upstream authorization proxy if needed. | **partial** — deployment-dependent. See RR-11. |
| T-02 | A-01 input | **T**ampering | MITM modifies input in transit | `confidential-ml-transport` AEAD (ChaCha20-Poly1305) with per-session key; attestation-bound; input hash in receipt | **mitigated** |
| T-03 | A-01 input | **I**nformation disclosure | Hypervisor reads plaintext input from enclave memory | TEE memory isolation (hardware). Verified by attestation chain. | **mitigated in-model** (TB-3). Residual: hardware CVEs (TA-8). |
| T-04 | A-01 input | **R**epudiation | Tenant denies sending the input | Receipt carries SHA-256 of the request body that reached the enclave. This proves *some* request reached the enclave and was served, but does **not** cryptographically bind the request to a specific external tenant identity — the gateway bearer token (when present) is a shared secret, and the transport-layer pubkey in REPORT_DATA is the gateway-side transport application's key, not the end-user's. Attestation-layer non-repudiation of the end caller is **not established today**. See RR-08. | **not mitigated for external tenant identity**; partial (enclave receives + processes a well-formed request) |
| T-05 | A-01 input | **I**nformation disclosure | Enclave logs contain plaintext prompts | Structured logging redacts fields; explicit deny-list of input/output logging at `tracing::debug` level | **mitigated** (code audit 2026-03; see `audit.rs`) |
| T-06 | A-02 output | **T**ampering | Host modifies model output before it leaves enclave | Output hash included in receipt; receipt signed by enclave-resident Ed25519 key; tampered output → hash mismatch when client verifies | **mitigated** |
| T-07 | A-02 output | **I**nformation disclosure | Attacker intercepts response on wire | Same AEAD as T-02 | **mitigated** |
| T-08 | A-03 model weights | **T**ampering | Compromised storage serves altered weights | Model manifest with SHA-256 + publisher's Ed25519 signature; enclave verifies before loading; hash in AIR v1 receipt as `model_hash` claim | **mitigated** |
| T-09 | A-03 model weights | **I**nformation disclosure | Cloud operator exfiltrates decrypted model from enclave memory | Decryption happens in-enclave; memory isolated by TEE. Keys released only after attestation. | **mitigated in-model** (TB-3, TB-4). Residual: TA-8, TA-9. |
| T-10 | A-04 receipt | **T**ampering | Attacker modifies claims between enclave and client | COSE_Sign1 wrapping; signature covers full CWT claimset; any byte change → signature invalid | **mitigated** |
| T-11 | A-04 receipt | **R**epudiation | Enclave operator denies producing a specific receipt | Ed25519 signature binds receipt to a key committed in attestation evidence | **mitigated** |
| T-12 | A-05 signing key | **I**nformation disclosure | Operator extracts Ed25519 key from enclave | Key generated inside enclave on boot; `zeroize` on shutdown; never persisted to disk. Attacker needs hardware TEE compromise. | **mitigated in-model** (TB-3). Residual: TA-8. |
| T-13 | A-05 signing key | **E**levation of privilege | Rogue image shipped that leaks the key | CI-signed image + manifest; attestation evidence includes image measurement (MRTD / PCR / userData); client's verifier pins expected measurement | **partially mitigated** — depends on verifier-side measurement pinning being enabled. Open item: `A-005 Enforce MRTD pinning in production verification profile` (STATE.yaml). |
| T-14 | A-06 session keys | **I**nformation disclosure | Session keys leak | Ephemeral per handshake; transport v0.6 has Phase 2+ session key zeroization (SEC-705); forward secrecy via ephemeral X25519 | **mitigated** |
| T-15 | A-07 attestation doc | **T**ampering | Attacker forges attestation document claiming a patched TCB | Chain verification with vendor root + (for SEV-SNP) TCB binding via VCEK extensions (Phase 5 of 2026-04 audit); AMD SB-3019 / BadRAM remediation | **mitigated** (all TEE verifiers — see `references/amd-sev-snp-audit-2026-04-12/findings.md` and TDX M2 hardening) |
| T-16 | A-07 attestation doc | **R**eplay | Old attestation reused in new session | `nonce` field in REPORT_DATA / userData is per-handshake random; verifier checks match | **mitigated** |
| T-17 (GCP) | A-08 KEK | **I**nformation disclosure | Cloud KMS releases key to attacker's workload | KMS policy binds to CS attestation claims (container image digest + TDX measurements); WIP/WIF token exchange enforces at Google-side; DEK travels over HTTPS to attested enclave only | **mitigated** — E2E validated (GCP TDX + GCP GPU H100 CC 2026-02-27 evidence) |
| T-17 (AWS) | A-08 KEK | **I**nformation disclosure | AWS KMS releases key to attacker's workload | `Decrypt` with `RecipientInfo`: KMS verifies NSM attestation doc matches key policy (PCR0/PCR1/PCR2) and wraps DEK to the RSA-2048 ephemeral pubkey embedded in that specific attestation doc. Only the attested enclave holds the matching private key. | **mitigated** — E2E validated (AWS Nitro 2026-02-27 evidence) |
| T-17 (Azure) | A-08 KEK | **I**nformation disclosure | Azure Key Vault releases key to attacker's workload | AAD token issuance bound to Azure Attestation; AKV `release_key` policy pins attestation claims. Full app-layer E2E not yet validated; transport layer passes. | **planned** — defer to pilot E2E validation on Azure |
| T-18 | All | **D**enial of service | Attacker floods gateway with attestation-triggering requests | Per-IP sliding-window rate limit + concurrency semaphore (transport v0.5.0). Exhaustion risk: TEE enclaves are memory-constrained; oversubscription degrades gracefully | **partially mitigated** — rate limiting present; load-shedding policy under review |

### 5.2 Per-data-flow STRIDE

| ID | DF | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|---|
| D-01 | DF-2 | Spoofing (enclave) | Attacker stands up a fake non-TEE server and serves attestation from a real TEE elsewhere (relay) | Design-level argument: attestation binds the ephemeral handshake pubkey in REPORT_DATA, and the per-session nonce prevents naive replay. This is a structural design property, not a machine-checked proof. | **design-level argument only** — external review / ProVerif analysis pending (see §7) |
| D-02 | DF-2 | Spoofing (client) | Server-side denial: attacker requests attestation but has not proven they hold a valid session key | 3-message mutual handshake: server completes DH before responding with payload; failed key-confirmation in Msg3 aborts session | **mitigated** |
| D-03 | DF-2 | Tampering | Downgrade to weaker cipher | Single cipher suite (ChaCha20-Poly1305 + X25519 HPKE); no negotiation | **mitigated** by design |
| D-04 | DF-3 | Tampering | Hypervisor intercepts attestation quote request | Quote is signed by TEE firmware; untrusted hypervisor cannot modify without detection at verifier | **mitigated** |
| D-05 (GCP) | DF-4 (GCP) | Spoofing | Attacker presents forged attestation to Cloud Attestation / KMS | Google Cloud Attestation validates TDX quote against Intel roots + Google-maintained CS image measurements; KMS policy pins image digest and TDX measurements via WIP | **mitigated** — GCP path |
| D-05 (AWS) | DF-4 (AWS) | Spoofing | Attacker presents forged attestation document to AWS KMS | NSM signs with AWS Nitro root; KMS verifies chain and key-policy PCR conditions before accepting `RecipientInfo` call | **mitigated** — AWS path |
| D-06 | DF-5 | Information disclosure | KMS returns key over unencrypted channel | HTTPS mutual TLS; KEK arrives wrapped where provider supports it | **mitigated** |
| D-07 | DF-6 | Tampering | Storage returns tampered model blob | Enclave verifies SHA-256 + Ed25519 manifest signature before use | **mitigated** |
| D-08 | DF-8 | Information disclosure | Response intercepted on wire | Same AEAD as DF-2 | **mitigated** |
| D-09 | DF-9 | Tampering | Attacker replaces client's local receipt with a forged one | Receipt signed by enclave Ed25519 key committed in attestation; verifier re-validates signature independently | **mitigated** |

## 6. Residual risks (honest accounting)

These are risks the current design cannot fully eliminate. Each is accepted, documented, and explained to pilot partners.

| RR-ID | Risk | Mitigation today | Compensating controls |
|---|---|---|---|
| RR-01 | Hardware TEE vulnerabilities (BadRAM, CacheWarp, Heckler, future unknowns) | TCB binding (F1 / BadRAM remediation); fast re-attestation on firmware updates | Subscribe to AMD / Intel / AWS security bulletins; enforce minimum TCB version per deployment; don't re-use keys across firmware versions |
| RR-02 | Side-channel attacks from peer tenants on same host (TA-9) | Vendor TEE isolation (AMD SEV-SNP PSP, Intel TDX SEAM) | Physical isolation via dedicated cloud SKUs where available; SINGLE_SOCKET policy for SEV-SNP deployments |
| RR-03 | Compromise of vendor root keys (TEE CA) | None — this is a trust base | Independent observability: evidence published to tamper-evident log (future). Would detect widespread issuance of anomalous quotes. |
| RR-04 | KMS-provider insider compromise releases keys without enclave being attested | KMS policy bound to attestation claims; audit logs on KMS side | Key policy reviewed per deployment; least-privilege IAM; alerting on unusual key-release patterns |
| RR-05 | Supply-chain attack on EphemeralML container image | CI-signed image; measurement in attestation; client-side measurement pinning (when enabled) | SBOM; reproducible builds (planned); signed container registry |
| RR-06 | No cryptographic proof of data deletion after session ends | Session keys zeroized; ephemeral memory cleared on shutdown; TEE memory is encrypted at rest (per vendor) | **Do not claim** "cryptographic proof of deletion" (C-102 in claim-language-guardrails). Wording: "session keys zeroized; processing is short-lived." |
| RR-07 | Availability of TEE-backed compute at scale | Rate limiting, concurrency caps | Capacity planning per pilot; graceful degradation to rejection (not to fallback non-TEE processing) |
| RR-08 | Non-repudiation of the caller is NOT established at the attestation layer | Receipt binds the SHA-256 of the request body that reached the enclave. There is no cryptographic binding of that body to a specific external tenant identity. The transport-layer pubkey attested in REPORT_DATA belongs to the gateway-side transport app (a trusted component), not the end user. | Deployments requiring per-tenant non-repudiation must layer upstream auth (e.g., mTLS at the gateway, signed request metadata from the tenant). Roadmap item: extend receipt claims to include a caller-identity claim when an authenticated upstream is present. |
| RR-11 | Gateway auth is a shared bearer token (optional) | Single `EPHEMERALML_API_KEY` compared in constant time. All holders are indistinguishable. | Upstream auth proxy per deployment; token rotation policy per pilot. Per-tenant identity at the gateway layer is a product roadmap item, not a current control. Do not claim multi-tenant isolation at this layer without it. |
| RR-09 | An attestation chain can be valid today but a retroactive vuln disclosure invalidates the TCB state the receipt attests to | Receipt captures TCB version; verifier can re-evaluate against current advisories | Publish "advisories page" with TCB version → CVE mapping; encourage re-verification cadence for long-retained receipts |
| RR-10 | Model published by a compromised model provider (TA-7) | Manifest signature pinned to a specific publisher Ed25519 key | Key rotation story + publisher revocation list needed (not yet implemented) |

## 7. Channel binding analysis (non-TLS — bounded design argument)

EphemeralML's channel is `confidential-ml-transport`, not TLS. We do not use `draft-fossati-tls-attestation` or `draft-interoperable-ra-tls`. This section states a **design-level argument** for why the relay and diversion attacks identified in Sardar, Moustafa, and Aura's *"Identity Crisis in Confidential Computing"* (ACM AsiaCCS 2026) **appear** not to apply to our protocol by the same paths. It is **not** a formal security proof, and has not yet been externally reviewed.

### Structural observation

In TLS-a and Interoperable RA-TLS, the server exposes two distinct identifiers: the long-term WebPKI TLS key (LTK) and the attestation key (AK). The diversion attacks exploit this bifurcation by binding the LTK of machine A to attestation from machine B.

In `confidential-ml-transport`, there is one identifier per session: the ephemeral X25519 public key used for the DH handshake, which is also the value committed in `REPORT_DATA[0..32]`. Attestation therefore binds directly to the session DH material rather than to a separate long-lived identity. We believe this removes the diversion-attack surface Sardar et al identify for TLS-based attested channels.

### What this argument is NOT

- **Not a ProVerif proof.** We have not yet written a formal model of the handshake.
- **Not externally reviewed.** Sardar et al have not evaluated our specific design.
- **Not exhaustive.** The argument covers the classes of attack they analyzed, not arbitrary channel-binding attacks.

### Status and pending work

- **Informal property-by-property evaluation** against the Sardar framework (7 properties: G-RA1/2/3, G-TLS1/2, G-C1/2) is drafted as a working memo; a polished version tied to the transport crate docs is a roadmap item.
- **Formal ProVerif analysis** of the handshake is a roadmap item estimated at 6-8 weeks. Not blocking pilot deployments; tied to AIR v1 IETF standardization milestone.
- **External review** by at least one independent cryptographer (potentially Sardar's group, per CCC Attestation SIG collaboration) before this section's claim strength is raised above "design-level argument."

External reviewers should treat D-01 in the STRIDE matrix and this section as **pending** rather than **settled**, and cite the structural argument only with the caveats above.

## 8. HIPAA §164.312 preliminary mapping

Preliminary — full mapping requires legal / compliance review before use in customer-facing material. See also `startup-plans/09-compliance/claim-language-guardrails.md` C-203 ("Tie compliance language to control mapping, not guarantees").

| HIPAA Control | Relevant EphemeralML mechanism | Threat IDs covered |
|---|---|---|
| §164.312(a) Access control | TEE isolation (TB-3); WIP-bound KMS (TB-4); gateway auth | T-03, T-09, T-17, D-05 |
| §164.312(b) Audit controls | AIR v1 receipt chain; structured tracing (`tracing`, `audit.rs`) | T-04, T-11, all |
| §164.312(c) Integrity | Receipt signature; model hash; request/response hashes in receipt | T-02, T-06, T-08, T-10, D-09 |
| §164.312(e) Transmission security | `confidential-ml-transport` AEAD; attestation-bound keys | T-02, T-07, T-14, D-03, D-08 |

## 9. Open questions / review items

- [ ] **RR-08** — should we require client-side request signing in a future protocol version? Product decision.
- [ ] **RR-10** — what's the model-publisher revocation story? Needed before customer publishes sensitive models through us.
- [ ] **T-13** — measurement pinning default in production verification profile (tracked as `A-005` in STATE.yaml).
- [ ] **T-18** — load-shedding policy: when the enclave pool is saturated, do we reject with attestation still, or fail open with explicit non-attested fallback? Fail-closed by default; explicit opt-in for non-attested. Needs docs.
- [ ] **§7** — commission ProVerif analysis of `confidential-ml-transport` binding (6-8 weeks; tied to AIR v1 IETF standardization milestone).
- [ ] **§8 HIPAA mapping** — legal review before customer-facing use.
- [ ] Azure SEV-SNP full app E2E — currently only transport-level. Blocked on pilot demand; not on technical gap.

## 10. Review cadence

- **Next scheduled review:** 2026-07-13 (quarterly), or upon any of:
  - New vendor security bulletin affecting any supported TEE
  - Change to handshake protocol (major version bump of `confidential-ml-transport`)
  - New threat actor category observed in real deployments
  - AIR v1 spec revision
- **Reviewers:** founder, external security consultant (pre-pilot), pilot partner security team (during pilot)

## 11. Document change log

| Version | Date | Change | Author |
|---|---|---|---|
| 0.1 | 2026-04-13 | Initial STRIDE decomposition; complements existing `SECURITY_MODEL.md` and `spec/v1/threat-model.md` | founder (drafted with assistance) |
| 0.2 | 2026-04-13 | Review-1 corrections: T-01 downgraded (gateway auth is a single shared bearer token, not per-tenant); T-04 rewritten to match RR-08 (no attestation-layer non-repudiation of external caller); TB-4 + DF-3/4/5 + T-17 + D-05 split per provider (GCP WIP ≠ AWS RecipientInfo ≠ Azure AAD-AKV); D-01 and §7 reframed as bounded design arguments pending formal analysis; added RR-11 (shared bearer token). Asset numbering continuous A-01..A-12. | founder (drafted with assistance) |

## 12. References

- `docs/SECURITY_MODEL.md` — upstream trust-model doc this builds on
- `spec/v1/threat-model.md` — AIR v1 receipt-format threat model
- `references/amd-sev-snp-audit-2026-04-12/findings.md` — SEV-SNP verifier audit + hardware validation
- `startup-plans/09-compliance/claim-language-guardrails.md` — wording rules for customer-facing statements
- IETF RFC 9334 — RATS architecture (roles, terminology)
- Sardar, Moustafa, Aura — *Identity Crisis in Confidential Computing: Formal Analysis of Attested TLS* — ACM AsiaCCS 2026 (referenced for structural argument in §7)
- AMD Security Bulletin SB-3019 / CVE-2024-56161 (BadRAM) — informs T-15 / RR-01
