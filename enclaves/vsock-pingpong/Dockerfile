# Build a minimal Nitro Enclave image (used by `nitro-cli build-enclave --docker-uri ...`).
# Produces a tiny static binary and runs it as PID 1.

FROM rust:1.75-alpine AS build

RUN apk add --no-cache musl-dev
WORKDIR /app

# Copy manifest + sources (crate is tiny; keep this simple and reliable)
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
# Use BusyBox (static) to minimize runtime dependencies and ensure /bin/sh exists.
FROM rust:alpine AS build

RUN apk add --no-cache musl-dev
WORKDIR /app

# Copy manifest + sources (crate is tiny; keep this simple and reliable)
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM busybox:1.36

COPY --from=build /app/target/x86_64-unknown-linux-musl/release/vsock-pingpong /vsock-pingpong
COPY init.sh /init
RUN chmod +x /vsock-pingpong /init

# Nitro's init/packager semantics are picky about how the command is derived.
# Empirically, relying on CMD alone can lead to an immediate reboot if the init
# can't determine what to exec. Define ENTRYPOINT explicitly.
#
# Mode is controlled via env so we can parameterize builds without depending on
# JSON-form CMD interpolation.
ARG MODE=vsock
ENV VSOCK_PINGPONG_MODE=${MODE}

ENTRYPOINT ["/init"]
CMD []
