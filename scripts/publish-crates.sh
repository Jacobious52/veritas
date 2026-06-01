#!/usr/bin/env bash
set -euo pipefail

mode="${1:---dry-run}"
if [[ "$mode" != "--dry-run" && "$mode" != "--execute" ]]; then
  echo "usage: $0 [--dry-run|--execute]" >&2
  exit 2
fi

packages=(
  veritas-plugin-api
  veritas-core
  veritas-report
  veritas-rust
  veritas-go
  veritas-python
  veritas-cli
)

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
if [[ -z "$version" ]]; then
  echo "failed to read workspace package version from Cargo.toml" >&2
  exit 1
fi

user_agent="veritas-release/0.1 (https://github.com/Jacobious52/veritas)"

crate_version_exists() {
  local crate="$1"
  local crate_version="$2"
  local status
  status="$(
    curl -L -sS -o /tmp/veritas-crate-version.json -w '%{http_code}' \
      -H "User-Agent: ${user_agent}" \
      "https://crates.io/api/v1/crates/${crate}/${crate_version}" || true
  )"
  [[ "$status" == "200" ]]
}

wait_for_crate_version() {
  local crate="$1"
  local crate_version="$2"
  for _ in {1..30}; do
    if crate_version_exists "$crate" "$crate_version"; then
      return 0
    fi
    sleep 10
  done
  echo "timed out waiting for ${crate} ${crate_version} to appear on crates.io" >&2
  return 1
}

publish_package() {
  local package="$1"
  local output
  local attempt
  for attempt in 1 2; do
    if output="$(cargo publish --locked -p "$package" 2>&1)"; then
      printf '%s\n' "$output"
      return 0
    fi

    if grep -Fq "Too Many Requests" <<<"$output" && [[ "$attempt" == "1" ]]; then
      local retry_after
      retry_after="$(sed -n 's/.*try again after \(.* GMT\).*/\1/p' <<<"$output" | head -n1)"
      local sleep_seconds="${VERITAS_RELEASE_RATE_LIMIT_SLEEP:-60}"
      if [[ -n "$retry_after" ]]; then
        local retry_epoch
        local now_epoch
        retry_epoch="$(date -u -d "$retry_after" +%s 2>/dev/null || true)"
        now_epoch="$(date -u +%s)"
        if [[ -n "$retry_epoch" && "$retry_epoch" -gt "$now_epoch" ]]; then
          sleep_seconds=$((retry_epoch - now_epoch + 5))
        fi
      fi
      local max_sleep="${VERITAS_RELEASE_MAX_RATE_LIMIT_SLEEP:-900}"
      if [[ "$sleep_seconds" -gt "$max_sleep" ]]; then
        printf '%s\n' "$output" >&2
        echo "crates.io rate-limit retry is ${sleep_seconds}s, above max ${max_sleep}s" >&2
        return 1
      fi
      echo "crates.io rate limit while publishing ${package}; retrying in ${sleep_seconds}s" >&2
      sleep "$sleep_seconds"
      continue
    fi

    printf '%s\n' "$output" >&2
    if grep -Fq "A verified email address is required" <<<"$output" \
      && [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      echo "::error title=crates.io email is not verified::Verify the email address on the crates.io account that owns CARGO_REGISTRY_TOKEN, then rerun the release workflow."
    fi
    return 1
  done
}

if [[ "$mode" == "--dry-run" ]]; then
  for package in "${packages[@]}"; do
    echo "==> Packaging ${package} ${version}"
    args=(package --locked -p "$package")
    if [[ "${VERITAS_RELEASE_ALLOW_DIRTY:-}" == "1" ]]; then
      args+=(--allow-dirty)
    fi
    # During the first workspace release, downstream crates depend on internal
    # crates that are not on crates.io yet. Patching crates.io to the local
    # workspace keeps dry-run verification meaningful without changing the
    # package manifest that will be uploaded.
    case "$package" in
      veritas-core | veritas-report)
        args+=(--config 'patch.crates-io.veritas-plugin-api.path="crates/veritas-plugin-api"')
        ;;
      veritas-rust | veritas-go | veritas-python)
        args+=(--config 'patch.crates-io.veritas-plugin-api.path="crates/veritas-plugin-api"')
        args+=(--config 'patch.crates-io.veritas-core.path="crates/veritas-core"')
        ;;
      veritas-cli)
        args+=(--config 'patch.crates-io.veritas-plugin-api.path="crates/veritas-plugin-api"')
        args+=(--config 'patch.crates-io.veritas-core.path="crates/veritas-core"')
        args+=(--config 'patch.crates-io.veritas-report.path="crates/veritas-report"')
        args+=(--config 'patch.crates-io.veritas-rust.path="crates/veritas-rust"')
        args+=(--config 'patch.crates-io.veritas-go.path="crates/veritas-go"')
        args+=(--config 'patch.crates-io.veritas-python.path="crates/veritas-python"')
        ;;
    esac
    cargo "${args[@]}"
  done
  exit 0
fi

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" && -n "${CRATES_IO_TOKEN:-}" ]]; then
  export CARGO_REGISTRY_TOKEN="${CRATES_IO_TOKEN}"
fi

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  message="CARGO_REGISTRY_TOKEN must be set for --execute. In GitHub Actions, set the repository secret named CARGO_REGISTRY_TOKEN."
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "::error title=Missing crates.io token::${message}"
  fi
  echo "${message}" >&2
  exit 1
fi

for package in "${packages[@]}"; do
  if crate_version_exists "$package" "$version"; then
    echo "==> ${package} ${version} already exists on crates.io; skipping"
    continue
  fi

  echo "==> Publishing ${package} ${version}"
  publish_package "$package"
  wait_for_crate_version "$package" "$version"
done
