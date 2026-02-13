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

# Build (mock mode, default)
cargo build

# Run tests
cargo test --workspace

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --workspace
```

### Feature Flags

- `mock` (default) — Local development without TEE hardware
- `production` — Real NSM attestation and VSock communication (AWS Nitro)
- `gcp` — Intel TDX attestation, direct TCP, WIF + Cloud KMS (GCP Confidential Space)
- `cuda` — GPU inference via Candle

**Mutually exclusive:** `mock`, `production`, and `gcp` cannot be combined (enforced by `compile_error!`).

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
   cargo fmt --check
   cargo clippy --workspace
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

The workspace has 4 main crates:

| Crate | Purpose |
|-------|---------|
| `common` | Shared crypto, protocol, types |
| `client` | Client library (attestation verification, policy) |
| `host` | Host relay proxy (KMS, S3, VSock forwarding) |
| `enclave` | TEE application (Nitro/TDX attestation, inference) |

See [`docs/design.md`](docs/design.md) for the full architecture.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
