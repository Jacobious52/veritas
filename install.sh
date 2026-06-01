#!/bin/sh
set -eu

repo="${VERITAS_REPO:-Jacobious52/veritas}"
version="${VERSION:-latest}"
install_dir="${INSTALL_DIR:-${VERITAS_INSTALL_DIR:-$HOME/.local/bin}}"

say() {
    printf '%s\n' "$*"
}

fail() {
    say "veritas install: $*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

download() {
    url="$1"
    output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$output" "$url"
    else
        fail "curl or wget is required"
    fi
}

case "$(uname -s)" in
    Linux) os="unknown-linux-gnu" ;;
    Darwin) os="apple-darwin" ;;
    *) fail "unsupported OS: $(uname -s)" ;;
esac

case "$(uname -m)" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

target="${arch}-${os}"
asset="veritas-${target}.tar.gz"
base_url="${VERITAS_BASE_URL:-https://github.com/${repo}/releases}"
if [ "$version" = "latest" ]; then
    download_url="${base_url}/latest/download"
else
    download_url="${base_url}/download/${version}"
fi

tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t veritas-install)"
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

archive="${tmpdir}/${asset}"
checksums="${tmpdir}/veritas-checksums.txt"

say "Installing veritas ${version} for ${target}"
download "${download_url}/${asset}" "$archive" || fail "failed to download ${asset}"

if download "${download_url}/veritas-checksums.txt" "$checksums" 2>/dev/null; then
    expected="$(grep "  ${asset}$" "$checksums" | awk '{print $1}' || true)"
    if [ -n "$expected" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            actual="$(sha256sum "$archive" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
        else
            actual=""
            say "veritas install: sha256sum or shasum not found; skipping checksum verification" >&2
        fi
        if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
            fail "checksum mismatch for ${asset}"
        fi
    else
        say "veritas install: checksum entry not found for ${asset}; skipping verification" >&2
    fi
else
    say "veritas install: checksums not found; skipping verification" >&2
fi

need tar
mkdir -p "$install_dir"
tar -xzf "$archive" -C "$tmpdir"
[ -x "${tmpdir}/veritas" ] || fail "archive did not contain executable veritas binary"

if command -v install >/dev/null 2>&1; then
    install -m 755 "${tmpdir}/veritas" "${install_dir}/veritas"
else
    cp "${tmpdir}/veritas" "${install_dir}/veritas"
    chmod 755 "${install_dir}/veritas"
fi

say "veritas installed to ${install_dir}/veritas"
case ":$PATH:" in
    *":${install_dir}:"*) ;;
    *) say "Add ${install_dir} to PATH to run veritas from any directory." ;;
esac

"${install_dir}/veritas" --version >/dev/null 2>&1 || "${install_dir}/veritas" --help >/dev/null
