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

# Runtime stage: avoid `scratch` while debugging Nitro's boot/init quirks.
# A tiny Alpine userspace makes behavior more predictable.
FROM alpine:3.19
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/vsock-pingpong /vsock-pingpong
RUN chmod +x /vsock-pingpong
CMD ["/vsock-pingpong"]
