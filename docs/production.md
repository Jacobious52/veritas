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

Before widening a plugin, run the seeded benchmark suite:

```bash
cargo run -p veritas-cli -- --root examples bench
```

The suite validates expected detections, required commands, runtime thresholds, mutation scores, property/fuzz quality metrics, and report metrics against temporary copies of realistic Rust and Go examples, so benchmark artifacts do not dirty the source examples.

For a concrete before/candidate/after evolution run, use the Go evolution fixture:

```bash
cargo run -p veritas-cli -- --root examples/go-evolution-loop verify --lang go --target .
cargo run -p veritas-cli -- --root examples/go-evolution-loop score
cargo run -p veritas-cli -- --root examples/go-evolution-loop evolve --dry-run
```

The seeded run starts with `14` evolution candidates, `12` selected, `4` surviving parser mutants, and score `55`. After promoting the top `ParseInvoiceTotal` candidate into owned assertions, the follow-up run reaches `91%` mutation score, `0` surviving mutants, and score `98`. See `docs/evolution.md` for the full artifact map and exact assertions.

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
min_mutation_score = 70
min_mutation_efficacy = 70
min_mutant_coverage = 80

[mutation]
# Shared mutation controls for Rust, Go, and future Tree-sitter plugins.
disabled_operators = []
exclude_paths = ["vendor/", "_generated.go$"]
dry_run = false
workers = 2 # Rust and Go use isolated temp roots for parallel mutants when enabled
test_cpu = 1
timeout_coefficient = 2
output_statuses = ["lived", "not_covered", "timed_out", "not_viable"]

[plugins.go]
fuzz_seconds = 5
fuzz_existing = true
fuzz_concurrency = 2
coverage_enabled = false
reverse_dependency_depth = 1
max_fuzz_targets = 5
command_timeout_seconds = 90
max_packages = 16
max_mutants = 4
build_tags = []
```

Use higher caps only for an explicit local investigation.

Reports include phase timings for discovery, generation, test execution, coverage, replay, artifact synthesis, and total runtime. Use those numbers before raising budgets: if coverage dominates, keep coverage disabled in CI; if replay dominates, narrow targets; if mutation dominates, lower `max_mutants`, use operator filters, or raise workers only on hosts that can absorb isolated project copies.

Set `policy.min_mutation_score`, `policy.min_mutation_efficacy`, and `policy.min_mutant_coverage` when you want Gremlins-style mutation quality gates. These thresholds are enforced after the report is scored, and they are language-neutral so Rust, Go, and future plugins share the same CI contract.

The `[mutation]` section is shared across plugins. Language plugins map generic operator names such as `arithmetic`, `comparison`, `boolean`, `bitwise`, `assignment`, `increment`, `loop`, `literal`, and `negation` to their tree-sitter mutation operators. `dry_run = true` records runnable mutants without executing package tests.

Go fuzz targets run through the shared scheduler with `fuzz_concurrency` as the per-repo cap. Keep this low in CI so fuzzing cannot starve normal package tests or mutation probes.

Rust and Go mutation can run in parallel when `[mutation].workers > 1`. Each mutant is applied inside an isolated temporary project copy, package tests run there, and the temporary root is removed when the worker finishes. `workers = 1` preserves the conservative serial source-rewrite behavior, which is often faster for small local examples because isolated cold Cargo builds can be expensive. Reports include requested workers, effective workers, isolated-copy setup milliseconds, and isolation failure counts; treat isolation failures as infrastructure problems, not killed mutants.

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
- `.veritas/assertions/*.json`
- `.veritas/corpus/*.json`
- `.veritas/corpus/replay_result.json`
- `.veritas/budgets/*.json`
- `.veritas/trends/*.json`
- `.veritas/feedback/*.md`
- `.veritas/mutations/*.txt`
- `.veritas/package_graph/*.json`
- `.veritas/symbol_graph/*.json`
- `.veritas/repros/*.md`
- `.veritas/patches/*.md`
- `.veritas/regressions/*.md`
- `.veritas/evolution/*.md`
- `.veritas/evolution/*_candidates.json`
- `.veritas/evolution/*_suite.json`
- `.veritas/evolution/*_generation_*.json`
- `.veritas/promotions/*.md`
- Rust `tests/veritas_generated*`
- Rust `tests/veritas_regression_*.rs`
- Go `veritas_fuzz_test.go`
- Go `veritas_regression_*_test.go`

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
- `veritas promote-regression` turns selected findings into ignored/skipped package-owned test scaffolds for Rust and Go; review and replace the placeholder before relying on them.
- `veritas evolve --dry-run` reads `.veritas/evolution/*_suite.json` and lists ranked candidates. `veritas evolve --index <n> --evaluate` or `--all-selected --evaluate` applies safe candidates as reviewable guidance or language-owned regression scaffolds, reruns scoped verification, and reports quality deltas.
- Differential checks persist API signatures, replay-case manifests, and replay result summaries. Treat them as the handoff point for comparing old/new behavior and promoting changed observations into assertions.
- `veritas replay-corpus` replays executable persisted corpus commands and skips guidance-only mutation entries until they are promoted into owned tests.
- `veritas score` summarizes mutation score, findings, assertion candidates, corpus entries/replay, replay cases, property strength, and budget health into one AI-change confidence view.
- `veritas accept-quality-baseline` records the reviewed quality floor used for later mutation and confidence deltas.

## External Canaries

Use pinned external canaries outside the normal fast loop:

```bash
./scripts/run-canaries.sh smoke
./scripts/run-canaries.sh verify-fast
./scripts/run-canaries.sh verify
```

See `docs/confidence.md` for pins and expected use.
