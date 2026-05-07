# Contributing to EphemeralML

Thank you for your interest in contributing to EphemeralML. This document provides guidelines for contributing to the project.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.75+ (stable toolchain)
- OpenSSL development headers (`libssl-dev` / `openssl-devel`)
- C/C++ compiler (`gcc`, `g++`)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/cyntrisec/EphemeralML.git
cd EphemeralML

# Build default feature set. Some application crates default to no mock feature;
# host tooling defaults to mock for local development.
cargo build --workspace

# Run tests
cargo test --workspace

# Check formatting
cargo fmt --all -- --check

# Run linter
cargo clippy --workspace --all-targets -- -D warnings
```

### Feature Flags

- `mock` — Local development without TEE hardware. Use explicitly for local demos and mock-mode tests.
- `production` — Real NSM attestation and VSock communication (AWS Nitro)
- `gcp` — Intel TDX / Confidential Space attestation, direct TCP, WIP + Cloud KMS via WIF (GCP Confidential Space)
- `cuda` — GPU inference via Candle

Default features differ by crate. The gateway, client, common, and enclave crates default to no platform feature; the host crate defaults to mock for local tooling. `mock`, `production`, and `gcp` are mutually exclusive where enforced by crate-level `compile_error!` guards.

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/cyntrisec/EphemeralML/issues/new?template=bug_report.md) with:
- Description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Rust version, instance type)

### Suggesting Features

Open a [Feature Request](https://github.com/cyntrisec/EphemeralML/issues/new?template=feature_request.md) describing the use case and proposed solution.

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes
4. Ensure all checks pass:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
5. Commit with a descriptive message
6. Push and open a Pull Request

### Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for new functionality
- Update documentation if behavior changes
- All CI checks must pass before merge

## Code Conventions

- **Rust 2021 edition**, stable toolchain only
- **Error handling**: Use typed errors with `thiserror`, propagate with `?`
- **Security**: `#[derive(ZeroizeOnDrop)]` on key material, constant-time comparisons
- **Naming**: `snake_case` functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` constants
- **Testing**: Inline `#[cfg(test)]` modules, descriptive test names
- **No unsafe** except minimal FFI/libc where required

## Architecture

The workspace has core runtime crates plus service/operator crates:

| Crate | Purpose |
|-------|---------|
| `common` | Shared crypto, protocol, types |
| `client` | Client library (attestation verification, policy) |
| `host` | Host relay proxy (KMS, S3, VSock forwarding) |
| `enclave` | TEE application (Nitro/TDX attestation, inference) |
| `gateway-api` | OpenAI-compatible HTTP gateway |
| `verifier-api` | Hosted verifier / Verification Center API |
| `compliance` | Evidence bundle and control-profile verification |
| `ephemeralml-doctor`, `ephemeralml-smoke-test` | AWS BYOC preflight and smoke-test tooling |

See [`docs/design.md`](docs/design.md) for the full architecture.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
