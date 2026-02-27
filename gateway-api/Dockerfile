# Multi-stage build for the EphemeralML OpenAI gateway.
# Produces a minimal image (~30MB) with just the gateway binary.

FROM rust:slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Copy workspace manifests first (layer cache)
COPY Cargo.toml Cargo.lock ./
COPY common/Cargo.toml common/Cargo.toml
COPY client/Cargo.toml client/Cargo.toml
COPY host/Cargo.toml host/Cargo.toml
COPY enclave/Cargo.toml enclave/Cargo.toml
COPY verifier-api/Cargo.toml verifier-api/Cargo.toml
COPY gateway-api/Cargo.toml gateway-api/Cargo.toml
COPY compliance/Cargo.toml compliance/Cargo.toml

# Create stub lib.rs files so cargo can resolve workspace deps
RUN for d in common client host enclave verifier-api gateway-api compliance; do \
      mkdir -p "$d/src" && echo "" > "$d/src/lib.rs"; \
    done
# Create stub bin files for all workspace members with binaries
RUN echo "fn main() {}" > gateway-api/src/main.rs && \
    echo "fn main() {}" > verifier-api/src/main.rs && \
    echo "fn main() {}" > enclave/src/main.rs && \
    echo "fn main() {}" > host/src/main.rs && \
    mkdir -p enclave/src/bin host/src/bin compliance/src/bin && \
    echo "fn main() {}" > enclave/src/bin/orchestrator.rs && \
    echo "fn main() {}" > enclave/src/bin/benchmark_baseline.rs && \
    echo "fn main() {}" > enclave/src/bin/vsock_echo.rs && \
    echo "fn main() {}" > host/src/bin/spy_host.rs && \
    echo "fn main() {}" > host/src/bin/kms_proxy_host.rs && \
    echo "fn main() {}" > compliance/src/bin/compliance_cli.rs

RUN cargo build --release -p ephemeralml-gateway --features mock 2>/dev/null || true

# Copy real source
COPY common/ common/
COPY client/ client/
COPY gateway-api/ gateway-api/

# Invalidate cargo cache for crates whose source was overwritten from stubs
RUN touch common/src/lib.rs client/src/lib.rs gateway-api/src/main.rs

RUN cargo build --release -p ephemeralml-gateway --features mock

# Runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ephemeralml-gateway /usr/local/bin/

EXPOSE 8090
ENTRYPOINT ["ephemeralml-gateway"]
