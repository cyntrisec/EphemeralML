#!/bin/sh
# EphemeralML installer — downloads prebuilt CLI binaries from GitHub Releases.
#
# Usage:
#   curl -fsSL https://github.com/cyntrisec/EphemeralML/releases/latest/download/install.sh | bash
#
# Environment variables:
#   EPHEMERALML_INSTALL_DIR  — override install directory (default: ~/.ephemeralml/bin)

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

# ── preflight checks ────────────────────────────────────────────────────────

need_cmd curl
need_cmd tar
need_cmd sha256sum

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_TAG="linux" ;;
    *)      die "unsupported OS: $OS (only Linux is supported)" ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_TAG="amd64" ;;
    *)            die "unsupported architecture: $ARCH (only x86_64/amd64 is supported)" ;;
esac

# ── resolve latest release tag ───────────────────────────────────────────────

info "fetch" "resolving latest release..."

TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    || die "failed to fetch latest release from GitHub API"

[ -n "$TAG" ] || die "could not determine latest release tag"

info "found" "$TAG"

# ── download tarball + checksums ─────────────────────────────────────────────

BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
TARBALL="ephemeralml-${TAG}-${OS_TAG}-${ARCH_TAG}.tar.gz"

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
(cd "$TMPDIR" && sha256sum -c SHA256SUMS --ignore-missing) \
    || die "checksum verification failed — download may be corrupted"

# ── extract and install ──────────────────────────────────────────────────────

info "extract" "unpacking tarball..."
tar xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

EXTRACTED_DIR="${TMPDIR}/ephemeralml-${TAG}-${OS_TAG}-${ARCH_TAG}"
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
