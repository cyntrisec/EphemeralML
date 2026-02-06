# EphemeralML Quick Start Guide

## Prerequisites

1. **Install Rust**: Visit [rustup.rs](https://rustup.rs/) and follow the installation instructions.
2. **AWS CLI & Nitro CLI**: (For production) Required to build EIF and run on Nitro instances.

## Building the Project

### Mock Mode (Local Development)
```bash
cargo build
```

### Production Mode (Nitro Enclaves)
```bash
cargo build --features production --no-default-features
```

## Running the System

### 1. Mock Mode
The mock mode allows testing the complete flow locally.

**Start Enclave (Mock Server):**
```bash
cargo run -p ephemeral-ml-enclave
```

**Run Client/Host Integration:**
```bash
# In separate terminals
cargo run -p ephemeral-ml-host --bin kms_proxy_host
cargo run -p ephemeral-ml-client --bin commander
```

### 2. Production Mode (AWS)
See `infra/hello-enclave/HELLO_ENCLAVE_RUNBOOK.md` for a step-by-step guide to deploying on AWS.

## Verification

### Host Blindness (Spy Mode)
To verify that the host cannot see sensitive data:
```bash
cargo test -p ephemeral-ml-host --test spy_test
```

### End-to-End Integration
```bash
cargo test
```
