# Build a minimal Nitro Enclave image (used by `nitro-cli build-enclave --docker-uri ...`).
# Produces a tiny static binary and runs it as PID 1.

FROM rust:alpine AS build

RUN apk add --no-cache musl-dev g++ perl make
WORKDIR /app

# Embed run metadata into the enclave binary at build time.
# NOTE: Nitro enclaves cannot access EC2 IMDS, so the host passes INSTANCE_TYPE as a build-arg.
ARG GIT_COMMIT=unknown
ARG INSTANCE_TYPE=unknown
ENV GIT_COMMIT=${GIT_COMMIT}
ENV INSTANCE_TYPE=${INSTANCE_TYPE}

# Build context is the repo root. Copy manifests first for better caching.
# Workspace root Cargo.toml is required for workspace dependency inheritance.
# We trim the workspace members to only what we need for the enclave build.
COPY Cargo.toml ./Cargo.toml
RUN sed -i 's/members = \[/members = [/' Cargo.toml && \
    sed -i '/"client"/d; /"host"/d; /"enclave"/d' Cargo.toml
COPY enclaves/vsock-pingpong/Cargo.toml ./enclaves/vsock-pingpong/Cargo.toml
COPY Cargo.lock* ./Cargo.lock
COPY common/Cargo.toml ./common/Cargo.toml

# Copy sources
COPY enclaves/vsock-pingpong/src ./enclaves/vsock-pingpong/src
COPY common/src ./common/src

# Build the enclave binary (musl)
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl --manifest-path enclaves/vsock-pingpong/Cargo.toml

FROM busybox:1.36

COPY --from=build /app/target/x86_64-unknown-linux-musl/release/vsock-pingpong /vsock-pingpong
COPY enclaves/vsock-pingpong/init.sh /init
RUN chmod +x /vsock-pingpong /init

# Nitro's init/packager semantics are picky about how the command is derived.
# Empirically, relying on CMD alone can lead to an immediate reboot if the init
# can't determine what to exec. Define ENTRYPOINT explicitly.
#
# Mode is controlled via env so we can parameterize builds without depending on
# JSON-form CMD interpolation.
ARG MODE=vsock
ENV VSOCK_PINGPONG_MODE=${MODE}

# PCR_MARKER: changing this value produces a different EIF with a different PCR0.
# Used by kms-audit wrong-PCR negative tests to verify that KMS rejects
# enclaves whose PCR0 doesn't match the key policy.
ARG PCR_MARKER=""
ENV PCR_MARKER=${PCR_MARKER}

ENTRYPOINT ["/init"]
CMD []
