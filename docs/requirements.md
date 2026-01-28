# Requirements Document

## Introduction

EphemeralML is a defense-in-depth confidential inference system that protects model weights and sensitive user inputs through a two-layer security architecture. Layer 1 (Gateway) provides TEE isolation with attestation-gated key release and end-to-end encrypted sessions where the host acts as a blind relay. Layer 2 (Shield Mode) adds optional leakage-resilient inference through structured weight obfuscation to make captured weights not directly usable under defined partial-compromise scenarios.

## Out of Scope (v1)

- Black-box model extraction/distillation via repeated queries
- Complete protection from all microarchitectural side-channels (timing/page-fault)
- Availability guarantees (host can DoS)
- Multi-cloud / confidential GPU support (future)
- Multi-model / arbitrary topology support
- Multi-tenant SaaS / user management / billing
- High availability / autoscaling / SLA guarantees
- GPU side-channel hardening guarantees
- Any claim of "model confidentiality under enclave compromise"

## Explicit Assumptions (v1)

- **A1. Client trust**: Client environment (or client-controlled verifier service) is trusted and holds the allowlist + policy root
- **A2. Nitro attestation roots**: AWS Nitro attestation root certificates are trusted for verifying attestation documents
- **A3. Host compromise**: Host OS is assumed fully compromised (root) and can observe/modify vsock traffic, scheduling, and storage; it cannot read enclave memory
- **A4. Network adversary**: On-path attacker can observe/modify network traffic between client and host
- **A5. KMS/Key Authority trust**: AWS KMS correctly enforces attestation-bound key release policy using RSA-2048 `RecipientInfo` to wrap secrets specifically for the verified enclave instance.
- **A6. Time source**: "Freshness" is provided via nonces + challenge/response (not wall-clock inside enclave)
- **A7. Side-channels**: Residual leakage via timing/access-patterns exists; only mitigations listed in-scope are claimed

## Glossary

- **Client**: The trusted entity that verifies attestation and establishes secure sessions
- **Host**: The untrusted EC2 instance that acts as a ciphertext-only relay
- **Enclave**: The AWS Nitro Enclave providing isolated, attested execution environment
- **Gateway**: Layer 1 security providing TEE isolation and attestation-bound sessions
- **Shield_Mode**: Layer 2 security providing leakage-resilient inference through obfuscation
- **Attestation_Document**: Cryptographically signed proof of enclave identity and measurements
- **AER**: Attested Execution Receipt providing audit evidence for each inference
- **E2E_Session**: End-to-end encrypted communication channel bound to enclave attestation
- **Key_Release_Policy**: Rules governing when encrypted model keys are released to enclaves
- **Enclave_Measurements**: Nitro Enclave measurements (e.g., PCR0..PCRn equivalents as reported in the attestation document) proving enclave code integrity
- **Measurement_Allowlist**: Client-maintained list of approved enclave measurements for key release
- **Model_DEK**: Per-model data encryption key (wrapped by KMS)
- **LRCI**: Leakage-Resilient Confidential Inference (Shield Mode implementation)

## Requirements

### Requirement 1: Attestation-Based Trust Establishment

**User Story:** As a client, I want to verify the enclave's identity and code integrity before releasing any secrets, so that I can ensure my data and models are processed by trusted code only.

#### Acceptance Criteria

1. WHEN establishing communication, THE Client SHALL verify the enclave's attestation document using Nitro attestation measurements
2. WHEN validating attestation, THE Client SHALL perform hardened verification including full COSE/CBOR parsing and AWS certificate chain validation (Leaf -> Intermediate -> Root CA) and verify measurements against client-maintained allowlist
3. WHEN attestation verification succeeds, THE Client SHALL establish an end-to-end encrypted session bound to the enclave's cryptographic identity
4. IF attestation fails or measurements don't match allowlist, THEN THE Client SHALL refuse to release any secrets
5. THE Client SHALL enforce freshness by including nonces in attestation challenges to prevent replay attacks
6. WHEN attestation documents are received, THE Client SHALL validate they are signed by authentic AWS Nitro hardware using full certificate chain validation
7. The Enclave SHALL generate an ephemeral session public key at boot/handshake and SHALL include it in the Attestation_Document (user-data) so the Client can bind the secure channel to the attested enclave instance

### Requirement 2: Attestation-Gated Key Release

**User Story:** As a security architect, I want model decryption keys released only to approved enclave measurements, so that encrypted models cannot be accessed by unauthorized or compromised code.

#### Acceptance Criteria

1. WHEN requesting model keys, THE System SHALL verify the requesting enclave matches approved measurements in the key release policy
2. WHEN key release policy is evaluated, THE System SHALL bind key access to specific enclave measurements and enclave versions
3. IF enclave measurements don't match policy, THEN THE System SHALL deny key release and log the security event
4. THE System SHALL support key rotation and revocation for compromised measurements
5. WHEN keys are released, THE System SHALL ensure they remain within the enclave boundary and are never exposed to the host
6. THE System SHALL implement time-bounded key access with automatic expiration for ephemeral sessions
7. Key release policy MUST be enforceable by an external authority (AWS KMS and/or a Key Broker). V1 uses AWS KMS for cryptographic enforcement; allowlist approval is enforced by the Client/Policy bundle
8. Freshness SHALL be verified by the Client and/or a dedicated Key Broker. KMS enforces measurement-bound authorization per policy
9. The System SHALL implement hardened attestation-bound key release where the Enclave generates an RSA-2048 keypair, embeds the public key in the attestation document's `public_key` field, and uses it as `RecipientInfo` for AWS KMS to wrap secrets specifically for that enclave.
10. Host proxy MUST be a byte-forwarder; it MUST NOT terminate TLS
11. Enclave MUST authenticate the KMS endpoint (pinned AWS CA set) and validate response structure
12. Proxy MUST be deny-by-default: only allow KMS + S3 endpoints explicitly

### Requirement 3: End-to-End Encrypted Sessions

**User Story:** As a client, I want my sensitive data encrypted end-to-end to the enclave, so that the host cannot read my inputs, outputs, or model information.

#### Acceptance Criteria

1. WHEN sending inference requests, THE Client SHALL encrypt all payloads using session keys bound to the enclave's attestation
2. WHEN the host receives encrypted payloads, THE Host SHALL forward them without decryption or inspection
3. THE System SHALL ensure only the verified enclave can decrypt client payloads using the session-bound keys
4. WHEN inference completes, THE Enclave SHALL encrypt results using the same session keys before returning to client
5. THE System SHALL use authenticated encryption to prevent tampering with encrypted payloads during transit
6. WHEN sessions terminate, THE System SHALL securely destroy all session keys and cryptographic material
7. Session establishment SHALL use HPKE (v1) and SHALL bind the session to: (a) attestation document hash, (b) enclave ephemeral public key, and (c) client nonce
8. The session key derivation SHALL bind a canonical transcript hash of: attestation_doc_hash || enclave_ephemeral_pubkey || client_nonce || protocol_version
9. HPKE suite MUST be fixed for v1 (X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
10. The Client SHALL reject sessions if attestation verification and channel binding do not match (prevents "attestation valid but key swapped" attacks)
11. Each request/response SHALL include replay protection (sequence number or per-message nonce policy) and the Enclave SHALL reject replays
12. All messages SHALL be framed as: version || session_id || seq_no || ciphertext || tag, with canonical encoding

### Requirement 4: Host as Blind Relay

**User Story:** As a system architect, I want the host to handle only encrypted data, so that host compromise cannot expose sensitive information.

#### Acceptance Criteria

1. THE Host SHALL forward encrypted payloads between client and enclave without accessing plaintext content
2. THE Host SHALL have no capability to decrypt client data, model weights, or inference results
3. WHEN storing encrypted model artifacts, THE Host SHALL maintain only ciphertext that is useless without enclave-bound keys
4. THE Host SHALL provide networking, storage, and AWS API access while remaining cryptographically blind to sensitive data
5. IF the host is compromised, THEN it SHALL contain no plaintext secrets, functional models, or decryption capabilities
6. THE Host SHALL implement secure communication channels (VSock) to the enclave without payload inspection

### Requirement 5: Secure Model Loading and Inference

**User Story:** As a model owner, I want my models decrypted and executed only within the trusted enclave, so that my intellectual property remains protected during inference.

#### Acceptance Criteria

1. WHEN loading models, THE Enclave SHALL decrypt model weights only within the trusted boundary using attestation-gated keys
2. THE Enclave SHALL execute all operations that must remain plaintext/trusted (tokenization, embedding lookup, mask/unmask, sampling, receipt signing)
3. THE Host/GPU SHALL execute only on obfuscated tensors and SHALL never observe plaintext prompts/weights
4. THE Enclave SHALL ensure no plaintext model weights, intermediate results, or sensitive data leak to the host
5. WHEN inference completes, THE Enclave SHALL immediately clear sensitive material from memory using secure erasure
6. THE Enclave SHALL support safetensors format for v1 (additional formats are future scope)
7. WHEN memory pressure occurs, THE Enclave SHALL fail securely without exposing sensitive data to the host
8. Sensitive buffers SHALL be explicitly zeroized and SHALL NOT rely on Drop semantics alone
9. Secure erasure SHALL be implemented using explicit zeroization for all sensitive buffers; the System SHALL document residual risks from allocator behavior and CPU cache/state as limitations

### Requirement 6: Attested Execution Receipts (AER)

**User Story:** As a compliance officer, I want cryptographic proof of what code processed each inference, so that I can audit and verify the integrity of sensitive computations.

#### Acceptance Criteria

1. WHEN inference completes, THE System SHALL generate an Attested Execution Receipt containing enclave measurements, request hash, and monotonic sequence number
2. WHEN creating receipts, THE System SHALL include the specific enclave build ID, policy version, and cryptographic nonce for uniqueness
3. THE System SHALL sign receipts using enclave-bound keys that prove the computation occurred within the verified trusted environment
4. THE Enclave SHALL generate the receipt signing key inside the enclave runtime and bind it cryptographically to the attestation document
5. THE System SHALL ensure receipts are cryptographically bound to enclave measurement, session, and request hash
6. WHEN clients receive receipts, THE System SHALL enable verification of receipt authenticity and binding to the specific inference request
7. THE System SHALL ensure receipts cannot be forged or replayed by unauthorized parties
8. WHEN audit trails are required, THE System SHALL provide receipt verification tools for compliance and forensic analysis
9. Receipt signing keys SHALL be ephemeral per session unless explicitly configured otherwise
10. AER MUST include: protocol version, security mode, enclave measurement(s), attestation doc hash, request hash, response hash (or output hash), policy version, and monotonic sequence number within the session
11. Request hash SHALL be computed over the canonical plaintext request structure before encryption
11. AER signature SHALL be verifiable by the Client using a public key whose authenticity is proven by being embedded in (or cryptographically bound to) the attestation document
12. The System SHALL provide a deterministic canonical encoding for AER fields (to avoid signature ambiguity)
13. Default receipt signing key lifetime SHALL be per-session
14. Receipt verification requires binding the receipt public key to attestation user-data
15. Timestamp is informational only and not relied on for security

### Requirement 7: Shield Mode (LRCI) - Leakage-Resilient Inference

**User Story:** As a security engineer, I want additional protection against partial boundary failures, so that captured memory dumps cannot yield directly usable model weights.

#### Acceptance Criteria

1. WHEN Shield Mode is enabled, THE System SHALL apply structured obfuscation to model weights using per-session masking factors
2. WHEN obfuscation is applied, THE System SHALL ensure masked weights are not directly usable without session-specific secrets
3. THE System SHALL generate unique masking factors for each inference session that remain within the enclave boundary
4. WHEN Shield Mode operates, THE System SHALL maintain performance within acceptable bounds and provide performance gating controls
5. IF masking secrets are compromised, THEN THE System SHALL gracefully degrade to Layer 1 (Gateway) protection only
6. THE System SHALL clearly document the specific attacker model that Shield Mode targets (memory scraping, partial compromise)
7. WHEN generating receipts, THE System SHALL include the security mode (Gateway-only vs Shield Mode) in receipt metadata
8. Shield Mode v1 SHALL implement keyed permutation+scaling masking for in-memory weights and tensors. The primitive SHALL define: key derivation, rotation frequency, and what attacker observations it is intended to resist
9. Shield Mode v1 SHALL NOT claim to preserve model confidentiality under full compromise of the enclave runtime (keys exposed); it targets partial compromise of Host/GPU artifacts and observational leakage
10. Shield Mode MUST NOT change model outputs beyond tolerance: token-level exact match rate ≥ 99% on a fixed evaluation set (eval/v1_prompts.jsonl)

### Requirement 8: Ephemeral Session Management

**User Story:** As a security architect, I want inference sessions to be short-lived and isolated, so that the exposure window for sensitive data is minimized.

#### Acceptance Criteria

1. WHEN sessions are created, THE System SHALL implement time-bounded sessions with automatic expiration
2. WHEN sessions terminate, THE System SHALL securely destroy all session keys, masking factors, and sensitive material (see Requirement 5.7 for zeroization requirements)
3. THE System SHALL ensure session isolation so that no sensitive data leaks between different inference sessions
4. WHEN multiple sessions run concurrently, THE System SHALL maintain strict separation of cryptographic material and model data
5. THE System SHALL implement session lifecycle management with proper cleanup on both normal and error termination
6. WHEN sessions expire, THE System SHALL prevent any further operations using expired session credentials

### Requirement 9: Security Event Logging and Monitoring

**User Story:** As a security operations team, I want comprehensive logging of security events, so that I can detect and respond to potential attacks or policy violations.

#### Acceptance Criteria

1. WHEN attestation events occur, THE System SHALL log verification results, measurement values, and policy decisions with timestamps
2. WHEN security violations are detected, THE System SHALL generate immutable audit records without exposing sensitive data
3. THE System SHALL track key release events, session establishment, and termination for security monitoring
4. WHEN suspicious activities are detected, THE System SHALL alert security teams while maintaining confidentiality of operations
5. THE System SHALL provide audit trails that enable forensic analysis without compromising ongoing security
6. WHEN compliance reporting is required, THE System SHALL generate reports that demonstrate adherence to security policies
7. Logs SHALL NOT include plaintext prompts, outputs, weights, session keys, or masking secrets
8. Receipts SHALL store only cryptographic hashes of sensitive data, never plaintext values
9. Observability data SHALL be split into: (a) security logs (events), (b) receipts (client-verifiable), (c) performance metrics (aggregated). Each category SHALL have a defined redaction/hashing policy

### Requirement 10: Error Handling and Secure Failure

**User Story:** As a system administrator, I want the system to fail securely under all error conditions, so that failures cannot be exploited to bypass security controls.

#### Acceptance Criteria

1. IF attestation verification fails, THEN THE System SHALL terminate sessions immediately and prevent any secret release
2. WHEN memory allocation fails, THE System SHALL clean up partial operations and securely clear any sensitive material
3. IF communication errors occur, THEN THE System SHALL maintain security boundaries during error recovery and cleanup
4. WHEN cryptographic operations fail, THE System SHALL abort operations securely without exposing intermediate states
5. THE System SHALL provide diagnostic information for troubleshooting without revealing sensitive data or security details
6. WHEN system limits are exceeded, THE System SHALL enforce resource controls while maintaining security guarantees
7. Core dumps MUST be disabled on Host and Enclave processes in production
8. Panic handlers MUST avoid formatting sensitive buffers

### Requirement 11: Performance and Scalability

**User Story:** As a system operator, I want the security measures to have minimal performance impact, so that confidential inference remains practical for production workloads.

#### Acceptance Criteria

1. THE System SHALL provide a benchmark suite and report overhead; no fixed SLA target is claimed for v1
2. WHEN Shield Mode is enabled, THE System SHALL maintain performance within configurable bounds and provide performance gating
3. THE System SHALL support concurrent inference sessions while maintaining security isolation and performance characteristics
4. WHEN scaling inference load, THE System SHALL handle multiple requests efficiently within enclave resource constraints
5. THE System SHALL optimize cryptographic operations to minimize latency impact on inference response times
6. THE System SHALL provide performance monitoring and alerting for security operations that impact system responsiveness
7. THE System SHALL include a benchmark suite and publish per-model performance metrics for transparency
8. Performance targets apply to warm sessions; cold-start latency SHALL be measured and reported separately
9. Benchmark methodology SHALL specify: model, instance type, batch/seq length, warm-up policy, and whether time includes attestation+handshake or inference-only
10. Performance targets for Gateway SHALL be measured with E2E encryption enabled and Host as blind relay enabled

### Requirement 12: Platform Integration and Deployment

**User Story:** As a DevOps engineer, I want seamless integration with AWS services and deployment pipelines, so that confidential inference can be deployed and managed in production environments.

#### Acceptance Criteria

1. THE System SHALL integrate with AWS KMS for key management with enclave identity binding and policy enforcement
2. WHEN deploying on AWS Nitro Enclaves, THE System SHALL support a reproducible deployment for a single-node pilot
3. THE System SHALL provide monitoring and logging integration with AWS CloudWatch and other observability tools
4. THE System SHALL integrate with AWS IAM for access control and policy management for administrative operations
5. THE System SHALL provide deployment validation tools to verify correct security configuration in production environments
6. All AWS API access required by the enclave SHALL be mediated via VSock proxy on the host and treated as untrusted transport
7. The Host SHALL run a dedicated "AWS API proxy" service that forwards enclave-originated requests (KMS, S3) and MUST NOT terminate E2E encryption or gain access to decrypted secrets
8. The Enclave SHALL treat all responses from the Host proxy as untrusted and SHALL authenticate/validate critical responses (e.g., ciphertext format, policy version, receipt fields)

### Requirement 13: Protocol Compatibility and Versioning

**User Story:** As a system maintainer, I want protocol versioning and compatibility rules, so that system updates don't break existing clients and deployments.

#### Acceptance Criteria

1. THE System SHALL implement versioned communication protocols with explicit version negotiation
2. WHEN protocol versions differ, THE System SHALL negotiate the highest mutually supported version
3. Protocol messages SHALL include a version field; v1 supports version 1 only
4. Version negotiation is reserved for v2
5. WHEN incompatible protocol versions are detected, THE System SHALL fail gracefully with clear error messages
6. THE System SHALL include protocol version information in attestation documents and receipts
7. WHEN deploying protocol updates, THE System SHALL provide migration tools and compatibility validation

### Requirement 14: Policy and Allowlist Management

**User Story:** As a security administrator, I want to update measurement allowlists and key release policies without redeploying client applications, so that I can respond to security events and manage enclave lifecycle.

#### Acceptance Criteria

1. Policy bundles MAY be updated without code changes, provided the client can fetch them from a configured location
2. Policy bundles SHALL be signed by a Client-trusted policy root and include version + expiry
3. The Client SHALL refuse expired or improperly signed policy bundles
4. WHEN policy updates are applied, THE System SHALL validate policy syntax and compatibility before activation
5. THE System SHALL maintain audit logs of all policy updates with timestamps and authorization details
6. WHEN policy conflicts occur, THE System SHALL use deny-by-default behavior and alert administrators

### Requirement 15: V1 Model Scope Constraints

**User Story:** As a system architect, I want clearly defined model scope for v1, so that implementation complexity remains manageable and testing is focused.

#### Acceptance Criteria

1. V1 SHALL support exactly one model family (Llama-3-8B) and one weights format (safetensors)
2. V1 supports dtype: BF16 only
3. Any other formats/models/dtypes are out of scope for v1
4. THE System SHALL validate model format and reject unsupported model types
5. WHEN unsupported models are requested, THE System SHALL return clear error messages indicating v1 limitations

## Non-Functional Security Requirements

- **NFR-S1 Supply-chain**: Reproducible enclave build; measurement derivation documented
- **NFR-S2 Crypto agility**: Crypto agility is a v2 requirement; v1 uses fixed HPKE suite and fixed AEAD
- **NFR-S3 Secure defaults**: Deny-by-default allowlist; Shield Mode off by default unless enabled