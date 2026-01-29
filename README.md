[![Status](https://img.shields.io/badge/Status-v1.0%20Complete-brightgreen?style=for-the-badge)]()
[![Tests](https://img.shields.io/badge/Tests-91%20Passing-success?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-AWS%20Nitro%20Enclaves-orange?style=for-the-badge&logo=amazon-aws)]()
[![Language](https://img.shields.io/badge/Rust-13k%20LOC-b7410e?style=for-the-badge&logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/Apache%202.0-blue?style=for-the-badge)]()

# 🔒 EphemeralML

**Confidential AI inference with hardware-backed attestation**

> Run AI models where prompts and weights stay encrypted — even if the host is compromised.

---

## Why EphemeralML?

| Problem | Solution |
|---------|----------|
| Cloud hosts can see your data | **TEE isolation** — data decrypted only inside the enclave |
| "Trust me" isn't enough | **Cryptographic attestation** — verify code before sending secrets |
| No audit trail | **Execution receipts** — proof of what code processed your data |

**Built for**: Defense, GovCloud, Finance, Healthcare — anywhere "good enough" security isn't.

---

## Architecture

```
┌─────────┐      HPKE       ┌─────────────┐     VSock     ┌─────────────┐
│  Client │◄──────────────► │  Host (blind │◄────────────►│   Enclave   │
└─────────┘   encrypted     │    relay)   │    encrypted  └──────┬──────┘
                            └─────────────┘                      │
                                   │                             │ NSM
                                   │ S3                          ▼
                            ┌──────┴──────┐              ┌───────────────┐
                            │   Encrypted │              │    AWS KMS    │
                            │    Models   │              │ (key release) │
                            └─────────────┘              └───────────────┘
```

**Key insight**: Host never has keys. It just forwards ciphertext.

---

## Security Model

### What's Protected
- ✅ **Model weights** (IP protection)
- ✅ **Prompts & outputs** (PII / classified data)
- ✅ **Execution integrity** (verified code)

### How
1. **Attestation-gated key release** — KMS releases DEK only if enclave PCRs match policy
2. **HPKE encrypted sessions** — end-to-end encryption, host sees only ciphertext
3. **Ed25519 signed receipts** — cryptographic proof of execution

### Threat Model
- ✓ Compromised host OS → **Protected** (enclave isolation)
- ✓ Malicious cloud admin → **Protected** (can't decrypt)
- ✓ Supply chain attack → **Detected** (PCR verification)
- ✓ Model swap attack → **Prevented** (signed manifests)

---

## Features

### Core (Production Ready)
- **Nitro Enclave integration** with real NSM attestation
- **AWS KMS** key release via RSA-2048 SPKI handshake
- **VSock protocol** for host↔enclave communication
- **S3 model storage** with client-side encryption

### Inference Engine
- **Candle-based** transformer inference (MiniLM, BERT, Llama)
- **GGUF support** for quantized models (int4, int8)
- **BF16/safetensors** format enforcement
- Memory-optimized for TEE constraints

### Security & Compliance
- **Attested Execution Receipts** (AER) for audit
- **Policy update system** with signature verification and hot-reload
- **Model format validation** (safetensors, dtype enforcement)
- **91 unit tests** across 4 crates
- **Deterministic builds** for reproducibility

---

## Quick Start

### Prerequisites
- AWS account with Nitro Enclave support
- Rust 1.75+ (for local development)
- Terraform (for infrastructure)

### Deploy
```bash
# 1. Provision infrastructure
cd infra/hello-enclave
terraform init && terraform apply

# 2. Build enclave image
./scripts/build_enclave.sh

# 3. Run
nitro-cli run-enclave --eif-path enclave.eif --cpu-count 2 --memory 4096
```

See [`QUICKSTART.md`](QUICKSTART.md) for detailed instructions.

---

## Project Status

| Component | Status | Tests |
|-----------|--------|-------|
| NSM Attestation | ✅ Production | 11 |
| KMS Integration | ✅ Production | — |
| VSock Protocol | ✅ Production | 11 |
| HPKE Sessions | ✅ Production | 8 |
| Inference Engine | ✅ Production | 4 |
| Receipt Signing | ✅ Production | 6 |
| Policy System | ✅ Production | 9 |
| Model Validation | ✅ Production | 21 |
| Compliance Tools | ✅ Production | — |
| Attestation Verifier | ✅ Production | 8 |

**v1.0 Gateway Complete** — 104/104 required tasks done, E2E verified on AWS Nitro.

---

## Documentation

- [`docs/design.md`](docs/design.md) — Architecture & threat model
- [`docs/tasks.md`](docs/tasks.md) — Implementation progress
- [`QUICKSTART.md`](QUICKSTART.md) — Deployment guide
- [`SECURITY_DEMO.md`](SECURITY_DEMO.md) — Security walkthrough

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

<div align="center">

**Run inference like the host is already hacked.**

[Documentation](docs/) • [Issues](https://github.com/tsyrulb/EphemeralML/issues)

</div>
