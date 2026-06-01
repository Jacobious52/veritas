#!/usr/bin/env bash
set -euo pipefail

mode="${1:-smoke}"
case "$mode" in
  smoke | verify | verify-fast) ;;
  *)
    echo "usage: $0 [smoke|verify|verify-fast]" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
canary_root="${VERITAS_CANARY_ROOT:-${repo_root}/target/external-fixtures}"
report_dir="${VERITAS_CANARY_REPORT_DIR:-${canary_root}/reports}"
mkdir -p "${report_dir}"

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
  run_veritas scan --root "${path}" --format json >"${report_dir}/${name}-scan.json"
  run_veritas scan --root "${path}" >/tmp/veritas-canary-${name}-scan.md

  if should_verify_canary "${name}"; then
    echo "==> verifying ${name}"
    run_veritas verify --root "${path}" --lang "${lang}" --target . >"${report_dir}/${name}-verify.md"
    cp "${path}/.veritas/report.json" "${report_dir}/${name}-report.json"
    run_veritas cleanup --root "${path}"
  fi
}

should_verify_canary() {
  local name="$1"
  if [[ "$mode" == "verify" ]]; then
    return 0
  fi
  if [[ "$mode" == "verify-fast" ]]; then
    case "$name" in
      rust-itoa | go-uuid) return 0 ;;
      *) return 1 ;;
    esac
  fi
  return 1
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

checkout_canary \
  rust-memchr \
  https://github.com/BurntSushi/memchr.git \
  ff7dca72388ade97ec536f550271fe5acab0a05f

checkout_canary \
  go-mux \
  https://github.com/gorilla/mux.git \
  db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265

cat >"${report_dir}/canaries.json" <<'JSON'
[
  {
    "name": "rust-itoa",
    "language": "rust",
    "repository": "https://github.com/dtolnay/itoa.git",
    "sha": "af77385d0daf4d0e949e81f2588be2e44f69f086"
  },
  {
    "name": "go-uuid",
    "language": "go",
    "repository": "https://github.com/google/uuid.git",
    "sha": "2d3c2a9cc518326daf99a383f07c4d3c44317e4d"
  },
  {
    "name": "rust-memchr",
    "language": "rust",
    "repository": "https://github.com/BurntSushi/memchr.git",
    "sha": "ff7dca72388ade97ec536f550271fe5acab0a05f"
  },
  {
    "name": "go-mux",
    "language": "go",
    "repository": "https://github.com/gorilla/mux.git",
    "sha": "db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265"
  }
]
JSON

run_smoke rust-itoa rust
run_smoke go-uuid go
run_smoke rust-memchr rust
run_smoke go-mux go

python3 "${repo_root}/scripts/canary-dashboard.py" "${report_dir}" "${mode}"

echo "==> canaries complete (${mode})"
echo "==> dashboard: ${report_dir}/canary-dashboard.md"
