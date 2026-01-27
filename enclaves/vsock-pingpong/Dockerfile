# Build a minimal Nitro Enclave image (used by `nitro-cli build-enclave --docker-uri ...`).
# Produces a tiny static binary and runs it as PID 1.

FROM rust:1.75-alpine AS build

RUN apk add --no-cache musl-dev
WORKDIR /app

# Cache deps
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl

# Build real app
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
# IMPORTANT: do NOT use "/bin/sh -c" in enclave images.
# If the shell or its dynamic loader fails, the enclave may reboot before our binary runs.
FROM alpine:3.19
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/vsock-pingpong /vsock-pingpong
RUN chmod +x /vsock-pingpong

# Run the Rust binary as PID 1.
ENTRYPOINT ["/vsock-pingpong"]

# Default mode; can be overridden via docker build args by replacing CMD at build time,
# or by passing args when debugging locally.
CMD ["--mode","vsock"]
