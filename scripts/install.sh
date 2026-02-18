#!/bin/sh
# EphemeralML installer — downloads prebuilt CLI binaries from GitHub Releases.
#
# Usage:
#   curl -fsSL https://github.com/cyntrisec/EphemeralML/releases/latest/download/install.sh | bash
#
# Environment variables:
#   EPHEMERALML_INSTALL_DIR  — override install directory (default: ~/.ephemeralml/bin)
#   EPHEMERALML_VARIANT      — force libc variant: "musl" or "gnu" (default: auto-detect)

set -eu

REPO="cyntrisec/EphemeralML"
INSTALL_DIR="${EPHEMERALML_INSTALL_DIR:-$HOME/.ephemeralml/bin}"

# ── helpers ──────────────────────────────────────────────────────────────────

info()  { printf '  \033[1;32m%s\033[0m %s\n' "$1" "$2"; }
warn()  { printf '  \033[1;33m%s\033[0m %s\n' "warn:" "$1" >&2; }
die()   { printf '  \033[1;31m%s\033[0m %s\n' "error:" "$1" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# Portable SHA-256 checksum: works on Linux (sha256sum) and macOS (shasum -a 256).
# Usage: check_sha256 <file> <expected_hash>
check_sha256() {
    _file="$1"
    _expected="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        _actual=$(sha256sum "$_file" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        _actual=$(shasum -a 256 "$_file" | cut -d' ' -f1)
    else
        die "no sha256sum or shasum found — cannot verify checksum"
    fi
    [ "$_actual" = "$_expected" ] || die "checksum mismatch for $_file (expected $_expected, got $_actual)"
}

# ── preflight checks ────────────────────────────────────────────────────────

need_cmd curl
need_cmd tar

# ── detect platform ──────────────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_TAG="linux" ;;
    Darwin) OS_TAG="darwin" ;;
    *)      die "unsupported OS: $OS (supported: Linux, macOS)" ;;
esac

case "$ARCH" in
    x86_64|amd64)   ARCH_TAG="amd64" ;;
    aarch64|arm64)   ARCH_TAG="arm64" ;;
    *)               die "unsupported architecture: $ARCH (supported: x86_64/amd64, aarch64/arm64)" ;;
esac

# ── detect musl on Linux ─────────────────────────────────────────────────────

VARIANT=""
if [ "$OS_TAG" = "linux" ]; then
    if [ "${EPHEMERALML_VARIANT:-}" = "musl" ]; then
        VARIANT="-musl"
    elif [ "${EPHEMERALML_VARIANT:-}" = "gnu" ] || [ "${EPHEMERALML_VARIANT:-}" = "" ]; then
        # Auto-detect: check if ldd reports musl
        if command -v ldd >/dev/null 2>&1; then
            if ldd --version 2>&1 | grep -qi musl; then
                VARIANT="-musl"
            fi
        fi
        # Override: if EPHEMERALML_VARIANT is explicitly "gnu", keep empty
    fi
fi

PLATFORM="${OS_TAG}-${ARCH_TAG}${VARIANT}"
info "detect" "platform: $PLATFORM"

# ── resolve latest release tag ───────────────────────────────────────────────

info "fetch" "resolving latest release..."

TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    || die "failed to fetch latest release from GitHub API"

[ -n "$TAG" ] || die "could not determine latest release tag"

info "found" "$TAG"

# ── download tarball + checksums ─────────────────────────────────────────────

BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
TARBALL="ephemeralml-${TAG}-${PLATFORM}.tar.gz"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

info "download" "$TARBALL"
curl -fsSL -o "${TMPDIR}/${TARBALL}" "${BASE_URL}/${TARBALL}" \
    || die "failed to download ${BASE_URL}/${TARBALL}"

info "download" "SHA256SUMS"
curl -fsSL -o "${TMPDIR}/SHA256SUMS" "${BASE_URL}/SHA256SUMS" \
    || die "failed to download SHA256SUMS"

# ── verify checksum ──────────────────────────────────────────────────────────

info "verify" "checking SHA-256 checksum..."
EXPECTED_HASH=$(awk -v f="$TARBALL" '$2==f {print $1}' "${TMPDIR}/SHA256SUMS")
[ -n "$EXPECTED_HASH" ] || die "tarball $TARBALL not found in SHA256SUMS"
check_sha256 "${TMPDIR}/${TARBALL}" "$EXPECTED_HASH"

# ── extract and install ──────────────────────────────────────────────────────

info "extract" "unpacking tarball..."
tar xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

EXTRACTED_DIR="${TMPDIR}/ephemeralml-${TAG}-${PLATFORM}"
[ -d "${EXTRACTED_DIR}/bin" ] || die "unexpected tarball layout — missing bin/ directory"

mkdir -p "$INSTALL_DIR"

for bin in ephemeralml ephemeralml-verify ephemeralml-compliance ephemeralml-orchestrator; do
    if [ -f "${EXTRACTED_DIR}/bin/${bin}" ]; then
        cp "${EXTRACTED_DIR}/bin/${bin}" "${INSTALL_DIR}/${bin}"
        chmod +x "${INSTALL_DIR}/${bin}"
        info "install" "${INSTALL_DIR}/${bin}"
    fi
done

# ── post-install guidance ────────────────────────────────────────────────────

printf '\n'
info "done" "EphemeralML $TAG installed to $INSTALL_DIR"
printf '\n'

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        printf '  Add the following to your shell profile (~/.bashrc or ~/.zshrc):\n\n'
        printf '    export PATH="%s:$PATH"\n\n' "$INSTALL_DIR"
        printf '  Then restart your shell or run:\n\n'
        printf '    export PATH="%s:$PATH"\n\n' "$INSTALL_DIR"
        ;;
esac

printf '  Verify installation:\n\n'
printf '    ephemeralml --version\n\n'
