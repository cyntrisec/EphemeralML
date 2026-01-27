# Build a minimal Nitro Enclave image (used by `nitro-cli build-enclave --docker-uri ...`).
# Produces a tiny static binary and runs it as PID 1.

FROM rust:1.75-alpine AS build

RUN apk add --no-cache musl-dev
WORKDIR /app

# Cache deps (no dummy sources; just fetch)
COPY Cargo.toml Cargo.lock* ./
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo fetch

# Build real app
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
# Use BusyBox (static) to minimize runtime dependencies and ensure /bin/sh exists.
FROM busybox:1.36

COPY --from=build /app/target/x86_64-unknown-linux-musl/release/vsock-pingpong /vsock-pingpong
COPY init.sh /init
RUN chmod +x /vsock-pingpong /init

# IMPORTANT: Nitro's `build-enclave` uses the container **CMD** as the program to exec
# (and may ignore ENTRYPOINT). So CMD must be the full argv starting with the executable.
CMD ["/init","--mode","vsock"]
