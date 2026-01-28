# Design: Inter-Enclave Trust with AWS Private CA

## Overview
EphemeralML requires a robust mechanism for multiple enclaves to trust each other (e.g., a Gateway enclave talking to an Inference enclave). While Nitro Attestation provides hardware-rooted identity, verifying raw attestation documents on every internal request is computationally expensive and complex.

This design proposes using **AWS Private Certificate Authority (Private CA)** and **ACM for Nitro Enclaves** to establish a standard TLS-based trust model.

## Architecture

### 1. Root of Trust
- A **Private CA** is created specifically for the EphemeralML environment.
- The Root CA certificate is embedded in all enclaves as a trusted root.

### 2. Identity Issuance (ACM for Nitro Enclaves)
- Each enclave type (Gateway, Inference) is assigned a unique DNS name (e.g., `inference.ephemeral-ml.internal`).
- An ACM certificate is requested for these names, backed by the Private CA.
- The parent instance's IAM role is granted permission to access the certificate.
- The **ACM for Nitro Enclaves** helper tool runs inside the enclave, performs attestation to ACM, and securely retrieves the certificate and private key.

### 3. Mutual TLS (mTLS) Comms
- Enclaves communicate over **AF_VSOCK** using standard TLS.
- Enclave A (Client) verifies Enclave B (Server) against the Private CA Root.
- Enclave B verifies Enclave A's client certificate against the Private CA Root.
- This ensures that only authorized EphemeralML enclaves can participate in the mesh.

## Hardening with KMS
- KMS keys used for model decryption can be further restricted to only be usable if the caller has a valid identity issued by the Private CA (using `kms:RecipientAttestation` conditions).

## Advantages
- **Standard Tooling**: Uses standard OpenSSL/Rustls for secure comms.
- **Revocation**: Supports CRLs/OCSP via Private CA.
- **Scalability**: New enclaves can join the trust mesh without updating existing enclaves' allowlists (as long as they share the same CA).

## Future Roadmap
- Implement **SPIFFE/SPIRE** integration for more dynamic identity management.
- Use **CloudHSM** as the backing store for the Private CA Root to meet higher compliance requirements.
