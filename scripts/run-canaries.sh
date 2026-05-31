#!/usr/bin/env bash
set -euo pipefail

mode="${1:-smoke}"
case "$mode" in
  smoke | verify) ;;
  *)
    echo "usage: $0 [smoke|verify]" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
canary_root="${VERITAS_CANARY_ROOT:-${repo_root}/target/external-fixtures}"

run_veritas() {
  if [[ -n "${VERITAS_BIN:-}" ]]; then
    "${VERITAS_BIN}" "$@"
  else
    cargo run -p veritas-cli -- "$@"
  fi
}

checkout_canary() {
  local name="$1"
  local url="$2"
  local sha="$3"
  local dest="${canary_root}/${name}"

  mkdir -p "${canary_root}"
  if [[ ! -d "${dest}/.git" ]]; then
    git init -q "${dest}"
    git -C "${dest}" remote add origin "${url}"
  fi
  git -C "${dest}" fetch -q --depth 1 origin "${sha}"
  git -C "${dest}" checkout -q --detach FETCH_HEAD
}

run_smoke() {
  local name="$1"
  local lang="$2"
  local path="${canary_root}/${name}"

  echo "==> scanning ${name}"
  run_veritas scan --root "${path}" >/tmp/veritas-canary-${name}-scan.md

  if [[ "$mode" == "verify" ]]; then
    echo "==> verifying ${name}"
    run_veritas verify --root "${path}" --lang "${lang}" --target .
    run_veritas cleanup --root "${path}"
  fi
}

cd "${repo_root}"

checkout_canary \
  rust-itoa \
  https://github.com/dtolnay/itoa.git \
  af77385d0daf4d0e949e81f2588be2e44f69f086

checkout_canary \
  go-uuid \
  https://github.com/google/uuid.git \
  2d3c2a9cc518326daf99a383f07c4d3c44317e4d

run_smoke rust-itoa rust
run_smoke go-uuid go

echo "==> canaries complete (${mode})"
