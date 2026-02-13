# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in EphemeralML, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use one of these channels:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/cyntrisec/EphemeralML/security/advisories/new)
2. **Email**: security@cyntrisec.com

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix**: Depends on severity; critical issues prioritized

## Scope

The following are in scope for security reports:

- **Cryptographic implementation** (HPKE, Ed25519, ChaCha20-Poly1305, COSE verification)
- **Attestation verification** (NSM document parsing, TDX quote verification, certificate chain validation, PCR/MRTD checks)
- **Key material handling** (zeroization, memory safety, key derivation)
- **Protocol security** (VSock/TCP message framing, session establishment, replay protection)
- **TDX envelope handling** (CBOR envelope parsing, receipt key propagation, measurement pinning)
- **Policy enforcement** (measurement allowlists, key release conditions, WIF token handling)
- **Input validation** (model format validation, safetensors parsing, CBOR/JSON deserialization)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.0.x   | Yes       |
| 2.0.x   | Yes       |
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Security Design

For details on the threat model and security architecture, see:

- [`docs/design.md`](docs/design.md) -- Architecture and threat model
- Internal security audit results are kept private; contact `security@cyntrisec.com` for reviewer access
- [`SECURITY_DEMO.md`](SECURITY_DEMO.md) -- Security verification walkthrough
