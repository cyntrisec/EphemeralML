# Investor Due Diligence: Cyntrisec / EphemeralML

*Code-based technical review — March 2026*
*No financials, cap table, or founder interviews conducted*

---

## Executive Summary

| Field | Value |
|-------|-------|
| **Company** | Cyntrisec |
| **Product** | EphemeralML — confidential AI inference with hardware-backed attestation |
| **Founder** | Borys Tsyrulnikov (sole contributor, 46/50 commits) |
| **Stage** | Pre-seed / technical founder |
| **License** | Apache 2.0 (open-source) |
| **Language** | Rust (136 source files, 7 crates) |
| **Tests** | 552 `#[test]` functions, CI with 12 jobs |
| **Version** | v3.1 (GPU Confidential) |
| **First commit** | 2026-02-26 |

---

## 1. Technology Assessment

### What It Does

EphemeralML runs AI inference inside hardware-isolated Trusted Execution Environments (TEEs) so that prompts, model weights, and outputs stay encrypted — even if the cloud host is compromised. Every inference produces a cryptographically signed receipt (AIR v1) proving what code processed what data.

### Architecture

7 workspace crates: `common`, `client`, `host`, `enclave`, `verifier-api`, `gateway-api`, `compliance`.

Supports three deployment targets:
- **AWS Nitro Enclaves** — NSM attestation, KMS key release, VSock communication
- **GCP Confidential Space** — Intel TDX attestation, configfs-tsm, Cloud KMS (WIP)
- **GPU TEE** — NVIDIA H100 CC-mode on GCP a3-highgpu-1g, Llama 3 8B inference

### Strengths (Green Flags)

| Signal | Evidence |
|--------|----------|
| **Deep technical execution** | 136 Rust source files, 552 test functions, 60 files with unit tests |
| **Production CI** | 12 CI jobs: fmt, clippy, test, mock-gate, build-gcp, build-aws-prod, smoke, compliance, deps, audit, shell-lint, release-gate |
| **Multi-cloud** | AWS Nitro + GCP Confidential Space + GPU H100 CC |
| **Real hardware benchmarks** | m6i.xlarge (AWS), a3-highgpu-1g (GCP). Load tests: 300 CPU requests (4 RPS, zero failures), 100 GPU requests (3.43 RPS, zero failures) |
| **Standards work** | IETF Internet-Draft (`draft-tsyrulnikov-rats-attested-inference-receipt-00`), NIST comment submitted |
| **Crypto quality** | HPKE, Ed25519, ChaCha20-Poly1305, COSE/CWT, CBOR, proper `zeroize` for key material |
| **Security audit integration** | `cargo audit` in CI (RUSTSEC-2023-0071 tracked with mitigation notes and review date) |
| **Mock isolation** | Dedicated CI job ensures `--allow-mock` never leaks into production builds |
| **Compliance framework** | 16 baseline controls, HIPAA mapping, automated evidence collection, `--strict` fail-closed mode |
| **Spec maturity** | AIR v1 frozen with CDDL schema, conformance vectors, interop kit, threat model |
| **Performance overhead** | +3-13% vs bare metal. Compliance overhead <2% of inference time |
| **Pilot-ready** | 30-min deploy guide, verify scripts, audit evidence templates |

### Concerns (Yellow/Red Flags)

| Concern | Severity | Detail |
|---------|----------|--------|
| **Solo developer** | **HIGH** | 46/50 commits by one person. Bus factor = 1. No code review visible |
| **Repo size: 9.2 GB** | MEDIUM | 10,433 files. Benchmark artifacts and evidence bundles bloating the repo. Should use Git LFS |
| **GCP KMS not wired** | MEDIUM | README states "Cloud KMS (WIP) — code exists, not wired into runtime" |
| **No paying customers** | **HIGH** | No pricing, billing, customer logos, or completed pilot evidence |
| **Apache 2.0 with no commercial layer** | MEDIUM | Anyone can fork. No enterprise tier, SaaS, or managed service |
| **Rapid commit cadence** | LOW | 50 commits in ~5 days suggests possible pre-demo sprint, not sustained velocity |
| **CUDA version lock** | LOW | GCP GPU locked to driver 535.x / CUDA 12.2 |

---

## 2. Market Assessment

### Target Verticals
Defense, GovCloud, Finance, Healthcare — regulated industries needing verifiable AI inference.

### Timing: Excellent
- **EU AI Act** (2026 enforcement) requires AI provenance and auditability
- **Executive Order 14110** creating US federal compliance demand
- **NIST AI RMF** driving standards adoption
- **Confidential computing market** projected $54B+ by 2028

### Competitive Landscape

| Competitor | Positioning | Differentiation |
|-----------|-------------|-----------------|
| Fortanix | Enterprise enclave platform | Generic, not AI-inference-specific |
| Anjuna | TEE runtime abstraction | Broader scope, not ML-focused |
| Opaque Systems | Confidential analytics (Spark) | Analytics, not real-time inference |
| Cloud providers | TEE hardware primitives | No attestation receipt layer or cross-cloud abstraction |
| **EphemeralML** | **Cross-cloud TEE inference + GPU CC + standardized receipt format (IETF draft) + compliance** | **Only OSS project combining all four** |

### Moat Analysis
- **Standards moat** (strong): IETF draft for AIR could become the receipt format. First-mover in RATS WG
- **Technical moat** (strong): Multi-cloud + GPU CC is rare. Most competitors are single-cloud
- **Compliance moat** (moderate): Built-in HIPAA, baseline controls with automated evidence
- **Business moat** (weak): Apache 2.0, no commercial differentiation yet

---

## 3. Team Assessment

### Founder: Borys Tsyrulnikov
- **Technical depth**: Exceptional — Rust, cryptography, TEEs, IETF standards, multi-cloud infra
- **Code quality**: Clean commit messages, structured CHANGELOG, proper security practices
- **Velocity**: High output in short timeframe

### Concern
- No co-founder (business/GTM)
- No advisory board visible
- No hiring plan visible

---

## 4. Business Model Assessment

### Current State: No Visible Revenue Model
- No pricing, SaaS offering, enterprise tier, or billing integration
- Pure open-source

### Recommended Paths to Explore
1. **Open-core**: Free OSS + paid enterprise features (audit dashboard, SLA, multi-tenant, SSO)
2. **Managed service**: "EphemeralML Cloud" — deploy in customer's cloud with management plane
3. **Compliance-as-a-Service**: Receipt verification + audit trail SaaS
4. **Professional services**: Deployment, integration, custom compliance profiles

---

## 5. Investment Scorecard

| Dimension | Score (1-5) | Notes |
|-----------|-------------|-------|
| Technology | **5/5** | Exceptional depth, real hardware validation, standards work |
| Market timing | **4/5** | Regulation tailwinds, growing demand for confidential AI |
| Team (current) | **2/5** | Solo founder, no GTM, no advisory |
| Business model | **1/5** | No revenue, no pricing, no commercial strategy |
| Competitive position | **4/5** | Unique cross-cloud + GPU + receipt + compliance combo |
| Traction | **1/5** | No customers, no LOIs, no pilots completed |
| **Overall** | **2.8/5** | |

---

## 6. Verdict: CONDITIONAL PASS

**The technology is outstanding** — genuinely rare deep-tech work that would take a well-funded team 12-18 months to replicate.

**Invest IF the founder demonstrates:**
1. A co-founder or 2-3 person team commitment
2. A clear commercial strategy (open-core or managed SaaS)
3. At least 1 LOI from a design partner in defense/finance/healthcare
4. A plan to transition from "impressive OSS project" to "fundable company"

---

## 7. Key Questions for the Founder

1. Have you spoken with potential customers? What does the pipeline look like?
2. What is your commercialization timeline?
3. Are you looking for a co-founder (business/GTM)?
4. What is your fundraising target and planned runway?
5. Have you considered YC, Techstars, or SBIR grants (defense angle)?
6. What happens to the IETF draft if Cyntrisec is acquired?
7. Can you demonstrate a customer deploying and verifying in <1 hour?
8. What is your plan for the GCP KMS gap?

---

## 8. Risk-Adjusted Summary

```
Technology risk:     LOW   (proven on real hardware, strong test coverage)
Market risk:         LOW   (regulation driving demand)
Execution risk:      HIGH  (solo founder, no team)
Business model risk: HIGH  (no revenue model defined)
Competition risk:    MEDIUM (cloud providers could build native)
```

**Bottom line**: This is a technically outstanding project with strong market tailwinds, held back by the absence of a team and business model. The founder should be taken seriously — the work product speaks for itself. The investment thesis hinges on whether Borys can build a team and find paying customers before the window closes.
