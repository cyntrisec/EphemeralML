# EphemeralML Quick Start Guide

## Prerequisites

1. **Install Rust**: Visit [rustup.rs](https://rustup.rs/) and follow the installation instructions
2. **Verify Installation**: Run `cargo --version` to confirm Rust is installed

## Project Structure

```
EphemeralML/
├── client/          # Client-side model decomposition and secure communication
├── host/            # Host proxy for weight storage and communication
├── enclave/         # Enclave-based ephemeral assembly and inference
├── tests/           # Integration tests
├── Cargo.toml       # Workspace configuration
└── README.md        # Project documentation
```

## Building the Project

### Option 1: Automated Build (Recommended)
```bash
python build.py
```

### Option 2: Manual Build
```bash
# Check workspace
cargo check

# Build in mock mode (default)
cargo build

# Build for production (requires AWS dependencies)
cargo build --features production --no-default-features
```

## Running Mock Mode

The project includes mock implementations for local development without AWS infrastructure.

### 1. Start Mock Enclave Server
```bash
cd enclave
cargo run
```
This starts a TCP server on port 8082 simulating the enclave.

### 2. Start Host Proxy (New Terminal)
```bash
cd host  
cargo run
```
This demonstrates weight storage and retrieval functionality.

### 3. Run Client (New Terminal)
```bash
cd client
cargo run
```
This demonstrates attestation verification and secure channel establishment.

## Testing

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration

# Validate project structure
python validate_structure.py
```

## Features

- **Mock Mode** (default): Local development with TCP communication
- **Production Mode**: AWS Nitro Enclaves with VSock and real attestation

## Mock Mode Components

### Client Mock Features
- Mock model decomposition
- Mock attestation verification  
- Mock secure channel establishment
- Mock encryption/decryption

### Host Mock Features
- TCP proxy instead of VSock
- In-memory weight storage
- Mock communication forwarding

### Enclave Mock Features
- Mock attestation document generation
- Mock model assembly and inference
- TCP server for communication
- Mock memory security operations

## Next Steps

1. **Verify Setup**: Run `python validate_structure.py`
2. **Build Project**: Run `cargo build`
3. **Test Mock Mode**: Follow the "Running Mock Mode" steps above
4. **Implement Features**: Continue with tasks from `.kiro/specs/ephemeral-inference/tasks.md`

## Troubleshooting

### Rust Not Found
- Install Rust from [rustup.rs](https://rustup.rs/)
- Restart your terminal after installation
- Verify with `cargo --version`

### Build Errors
- Ensure all dependencies are available
- Check that you're using Rust 1.70+
- Try `cargo clean` and rebuild

### Mock Mode Issues
- Ensure ports 8080-8082 are available
- Check firewall settings for local TCP connections
- Verify all three components are started in order

## Development Workflow

1. **Start with Mock Mode**: Develop and test locally using mock implementations
2. **Implement Core Logic**: Replace placeholder implementations with real functionality
3. **Add Tests**: Write unit and property-based tests for each component
4. **Production Deployment**: Build with production features for AWS deployment

This setup provides a solid foundation for developing the EphemeralNet zero-trust AI inference system.