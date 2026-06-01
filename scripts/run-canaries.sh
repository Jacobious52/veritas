#!/usr/bin/env bash
set -euo pipefail

mode="${1:-smoke}"
case "$mode" in
  smoke | verify | verify-fast | large-smoke) ;;
  *)
    echo "usage: $0 [smoke|verify|verify-fast|large-smoke]" >&2
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

include_large_canaries() {
  [[ "$mode" == "large-smoke" ]]
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

if include_large_canaries; then
  checkout_canary \
    rust-clap \
    https://github.com/clap-rs/clap.git \
    8141e110ecee321277e90b4baa22a5baa02813ea

  checkout_canary \
    go-gin \
    https://github.com/gin-gonic/gin.git \
    5f4f9643258dc2a65e684b63f12c8d543c936c67

  checkout_canary \
    python-click \
    https://github.com/pallets/click.git \
    c48021040a50c659b74e24ac2b11c9c9c6620a21
fi

python3 - "${report_dir}/canaries.json" "$mode" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
mode = sys.argv[2]
canaries = [
    {
        "name": "rust-itoa",
        "language": "rust",
        "profile": "baseline",
        "repository": "https://github.com/dtolnay/itoa.git",
        "sha": "af77385d0daf4d0e949e81f2588be2e44f69f086",
    },
    {
        "name": "go-uuid",
        "language": "go",
        "profile": "baseline",
        "repository": "https://github.com/google/uuid.git",
        "sha": "2d3c2a9cc518326daf99a383f07c4d3c44317e4d",
    },
    {
        "name": "rust-memchr",
        "language": "rust",
        "profile": "baseline",
        "repository": "https://github.com/BurntSushi/memchr.git",
        "sha": "ff7dca72388ade97ec536f550271fe5acab0a05f",
    },
    {
        "name": "go-mux",
        "language": "go",
        "profile": "baseline",
        "repository": "https://github.com/gorilla/mux.git",
        "sha": "db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265",
    },
]
if mode == "large-smoke":
    canaries.extend(
        [
            {
                "name": "rust-clap",
                "language": "rust",
                "profile": "large-repo",
                "repository": "https://github.com/clap-rs/clap.git",
                "sha": "8141e110ecee321277e90b4baa22a5baa02813ea",
            },
            {
                "name": "go-gin",
                "language": "go",
                "profile": "large-repo",
                "repository": "https://github.com/gin-gonic/gin.git",
                "sha": "5f4f9643258dc2a65e684b63f12c8d543c936c67",
            },
            {
                "name": "python-click",
                "language": "python",
                "profile": "large-repo",
                "repository": "https://github.com/pallets/click.git",
                "sha": "c48021040a50c659b74e24ac2b11c9c9c6620a21",
            },
        ]
    )
path.write_text(json.dumps(canaries, indent=2) + "\n")
PY

cat >"${report_dir}/canary-profiles.md" <<'MD'
# Canary Profiles

- `baseline`: small pinned public repositories used by the weekly smoke/verify jobs.
- `large-repo`: larger pinned public repositories used by `large-smoke` to exercise Tree-sitter discovery, target counting, and dashboard rollups without running expensive verification by default.
MD

run_smoke rust-itoa rust
run_smoke go-uuid go
run_smoke rust-memchr rust
run_smoke go-mux go
if include_large_canaries; then
  run_smoke rust-clap rust
  run_smoke go-gin go
  run_smoke python-click python
fi

python3 "${repo_root}/scripts/canary-dashboard.py" "${report_dir}" "${mode}"

echo "==> canaries complete (${mode})"
echo "==> dashboard: ${report_dir}/canary-dashboard.md"
