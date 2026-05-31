# Production Guide

`veritas` is built for branch and PR verification in large Rust and Go repositories. The production path is changed-scope, budgeted, low-noise, and adversarial.

## Operating Model

Use regular language tooling for normal correctness checks:

```bash
cargo test --workspace
go test ./...
```

Use `veritas` to attack changed and risky surfaces:

```bash
veritas review-ai
veritas verify --changed --profile ci
veritas report --format sarif
veritas report --format junit
```

The CI profile:

- implies `--changed`
- disables broad coverage collection
- caps package count, fuzz targets, fuzz time, mutation count, and command timeouts
- enables policy failure for error-or-higher findings

## Large Go Repositories

The Go plugin is package-aware:

- discovers one or more `go.mod` roots
- runs `go list -json ./...` per module
- maps selected artifacts and target IDs back to package directories
- includes configurable reverse dependencies
- applies `build_tags` to `go list`, `go test`, fuzzing, coverage, and mutation commands
- runs package commands from the owning Go module
- writes `.veritas/package_graph/go.json`
- writes `.veritas/feedback/go_packages.md`
- writes `.veritas/symbol_graph/go_*.json`

Recommended large-repo config:

```toml
[veritas]
budget_seconds = 120
fail_on_findings = true

[policy]
fail_on_severity = "error"

[plugins.go]
fuzz_seconds = 5
fuzz_existing = true
coverage_enabled = false
reverse_dependency_depth = 1
max_fuzz_targets = 5
command_timeout_seconds = 90
max_packages = 16
max_mutants = 4
build_tags = []
```

Use higher caps only for an explicit local investigation.

`fixtures/go-multimodule` is the local confidence fixture for this path. It has two Go modules, a cross-module import, a selected billing package, and a gateway reverse dependency. It also keeps a handwritten fuzz target so the generated-fuzz path proves it does not emit duplicate fuzz names.

## Rust Host Safety

Rust validation can be expensive on large workspaces. On Linux hosts with systemd user scopes, use:

```toml
[plugins.rust]
coverage_enabled = false
command_timeout_seconds = 120
coverage_timeout_seconds = 120
cargo_jobs = 1
test_threads = 1
systemd_scope = true
memory_max = "4G"
cpu_quota = "200%"
```

With `systemd_scope = true`, Rust commands are run through `systemd-run --user --scope` with `RuntimeMaxSec`, `MemoryMax`, and `CPUQuota` properties. The plugin also sets `CARGO_BUILD_JOBS` and `RUST_TEST_THREADS`.

## Failure Policy

Findings carry:

- severity: `info`, `warning`, `error`, or `critical`
- language
- artifact ID
- target risk
- stable finding ID

Policy can fail only selected findings:

```toml
[veritas]
fail_on_findings = true

[policy]
fail_on_severity = "error"
fail_on_languages = ["go", "rust"]
fail_on_artifact_kinds = []
fail_on_target_risks = []
```

For known accepted findings:

```bash
veritas accept-baseline --id <finding-id>
```

Accepted IDs are stored in `.veritas/baselines/findings.json`.

## Generated Artifacts

Common generated paths:

- `.veritas/report.json`
- `.veritas/ai/*.md`
- `.veritas/baselines/*.json`
- `.veritas/differential/*.json`
- `.veritas/feedback/*.md`
- `.veritas/mutations/*.txt`
- `.veritas/package_graph/*.json`
- `.veritas/symbol_graph/*.json`
- `.veritas/repros/*.md`
- `.veritas/patches/*.md`
- `.veritas/regressions/*.md`
- `.veritas/promotions/*.md`
- Rust `tests/veritas_generated*`
- Go `veritas_fuzz_test.go`

Clean generated artifacts with:

```bash
veritas cleanup --dry-run
veritas cleanup
```

`cleanup` skips build, VCS, dependency, and vendor directories.

## Production Boundaries

`veritas` deliberately keeps generated tests conservative. It discovers more symbols than it can always generate high-quality harnesses for:

- Rust property generation targets supported public free functions.
- Go fuzz generation targets exported free functions with supported primitive fuzz parameter types.
- Methods, unsupported signatures, and richer types are still included in target discovery, symbol graphs, mutation checks, package graphs, policy, and baselines.
- Coverage and fuzz repro extraction are best effort and depend on language tool output.
- Surviving mutants and minimized fuzz/proptest inputs become reviewable regression artifacts before they become committed tests.
- Differential checks persist API signatures and replay-case manifests; they do not yet execute old/new binaries automatically.

## External Canaries

Use pinned external canaries outside the normal fast loop:

```bash
./scripts/run-canaries.sh smoke
./scripts/run-canaries.sh verify
```

See `docs/confidence.md` for pins and expected use.
