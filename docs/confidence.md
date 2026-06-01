# Confidence Guide

`veritas` uses several layers of confidence checks. Keep fast checks in normal development and reserve external canaries for manual or scheduled runs.

## Local Test Layers

1. Unit tests in each crate cover parser helpers, report rendering, changed-target selection, cleanup, package scoping, mutation candidates, and artifact rendering.
2. Tiny fixtures in `fixtures/sample-rust`, `fixtures/sample-go`, and `fixtures/sample-python` keep the CLI smoke path fast across the plugin contract.
3. Medium fixtures exercise production shapes:
   - `fixtures/rust-workspace`: virtual Cargo workspace, multiple packages, public free functions, public methods, package-local generated proptests, and mutation feedback.
   - `fixtures/go-multimodule`: two Go modules, cross-module imports, reverse dependency scoping, handwritten fuzz discovery, generated fuzz suppression for duplicate names, package graph artifacts, and symbol graphs.
4. Seeded examples intentionally pass handwritten tests while generated verification exposes hidden assumptions:
   - `examples/rust-invoice`: parser assumptions and refund authorization.
   - `examples/go-invoice`: parser panics and token normalization.
   - `examples/rust-commerce`: checkout parsing, refund arithmetic, coupon boundaries, and permission defaults.
   - `examples/go-api-service`: API parameter parsing, token normalization, status mapping, and read authorization.
   - `examples/rust-mutation-score`: killed and surviving Rust mutants for mutation-score calibration.
   - `examples/go-mutation-score`: killed and surviving Go mutants for mutation-score calibration.
   - `examples/rust-risk-suite`: auth, money, parsing, serialization, and boundary mutants with known survivors.
   - `examples/go-risk-suite`: Go fuzzing plus mutation-score attribution across auth, parsing, and serialization surfaces.
   - `examples/rust-evolution-loop`: Rust refund, parsing, and status behavior with a multi-candidate evolution suite.
   - `examples/go-evolution-loop`: Go refund, parsing, and status behavior with a before/candidate/after evolution demo.
   - `examples/rust-concurrency-db`: tenant/idempotency, transaction, lock, atomic-ordering, retry/backoff, and thread-join mutation surfaces.
   - `examples/go-concurrency-db`: goroutine, deferred unlock, context, tenant/idempotency, transaction, retry/backoff, and atomic mutation surfaces.
5. Benchmark suites in `examples/veritas-bench.toml` run seeded examples in temporary copies and score expected findings, commands, thresholds, and metrics.

## Required Checks

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
VERITAS_RELEASE_ALLOW_DIRTY=1 ./scripts/publish-crates.sh --dry-run
```

## Fixture Dogfood

```bash
cargo run -p veritas-cli -- verify --root fixtures/rust-workspace --lang rust --target .
cargo run -p veritas-cli -- cleanup --root fixtures/rust-workspace

cargo run -p veritas-cli -- verify --root fixtures/go-multimodule --lang go --target services/billing/pkg/invoice
cargo run -p veritas-cli -- cleanup --root fixtures/go-multimodule
```

The medium fixtures intentionally produce mutation feedback. Treat that as an assertion that the feedback path is working, not as a fixture failure.

## Seeded Benchmark Suite

Run the local benchmark suite when changing generation, mutation, fuzzing, reporting, or plugin contracts:

```bash
cargo run -p veritas-cli -- --root examples bench
cargo run -p veritas-cli -- --root examples bench --format json
cargo run -p veritas-cli -- --root examples/rust-concurrency-db mutants list --lang rust --target src/lib.rs --diffs
cargo run -p veritas-cli -- --root examples/go-concurrency-db mutants list --lang go --target . --format json
```

Each benchmark case declares expected finding-message substrings, artifact kinds, command substrings, and thresholds such as `min_findings`, `min_commands`, `min_generated_test_failures`, and `max_duration_ms`. A suite can set `profile = "seeded"`, `profile = "large-repo"`, or `profile = "canary"` to separate small regression fixtures from scale/performance probes. The command copies each case to a temporary directory, runs `veritas verify`, writes the report inside that copy, and removes the copy when done. A case fails when an expected detection disappears, a required command is skipped, or a threshold is violated.

Benchmark JSON includes a suite summary for total targets, high-risk targets, commands, findings, artifacts, executed mutants, replay cases, selected evolution candidates, large-repo cases, total duration, and slowest case. Per-case metrics include target/function/package counts, coverage file counts, command count, finding counts by severity, artifact counts by kind, phase timings, mutation score, mutant generated/executed/killed/survived/skipped counts, mutation worker/isolation metrics, isolated copy cost separated from test execution, mutation trend artifacts, generated-test failure count, property strength metrics, assertion candidate count, corpus entry/replay count, replay case count, budget skip/timeout count, fuzz execution/failure counts, and persisted repro count. GitHub Actions runs the same seeded suite for benchmark-sensitive pull requests through `.github/workflows/benchmarks.yml`.

After a verification run, use `veritas score` as the compact confidence view for AI-driven changes. It rewards mutation score, property/fuzz/replay signal, and assertion candidates, and it penalizes active findings, surviving mutants, skipped commands, and timeouts. Use `veritas accept-quality-baseline` only after a reviewed good state; later `veritas score` runs will show baseline deltas.

Use `veritas score --mode all` for anti-gaming views. `current` is the normal report confidence, `strict` keeps accepted findings and skipped commands as score debt, and `verified` additionally treats unpromoted assertion/regression candidates and surviving mutants as proof debt. CI should gate on strict or verified when a repository wants confidence to improve only through real owned tests and passing proof commands.

Use `veritas badge` to render a local `.veritas/badge.svg` from the saved report. The badge includes confidence score, grade, and mutation score when available, so README and Pages examples can show a tangible verification signal without network services.

Use `veritas replay-corpus --dry-run` to inspect persisted repro metadata. Executable commands such as `go test` or `cargo test` can be replayed directly; mutation guidance entries are skipped until promoted into package-owned tests.

The concrete evolution reference is `docs/evolution.md`. It uses `examples/go-evolution-loop` to show a real report moving from `58%` mutation score, `4` surviving mutants, and score `55` to `91%` mutation score, `0` surviving mutants, and score `98` after a selected candidate becomes owned assertions.

## External Canaries

External canaries clone pinned public repositories into `target/external-fixtures`:

```bash
./scripts/run-canaries.sh smoke
./scripts/run-canaries.sh large-smoke
./scripts/run-canaries.sh verify-fast
./scripts/run-canaries.sh verify
```

Smoke mode scans each baseline repository and writes JSON scan summaries. Large-smoke mode adds larger pinned Rust, Go, and Python repositories (`rust-clap`, `go-gin`, and `python-click`) and keeps them scan-only by default so target discovery and dashboard rollups exercise scale without exhausting shared runners. Verify-fast mode scans every baseline canary and verifies the fast subset (`rust-itoa` and `go-uuid`). Verify mode runs `veritas verify --target .` for every baseline canary, copies each `.veritas/report.json` into `target/external-fixtures/reports`, and then cleans generated artifacts.

Both modes write a dashboard:

```text
target/external-fixtures/reports/canary-dashboard.md
target/external-fixtures/reports/canary-summary.json
target/external-fixtures/reports/canary-history.jsonl
target/external-fixtures/reports/canary-profiles.md
```

The dashboard assigns a real-repo tier per canary. `scan` means target discovery completed. Verify-mode `high`, `medium`, and `low` tiers come from the saved confidence score and finding count. If local history exists, the dashboard includes confidence, mutation, and finding deltas against the previous run for the same canary. Set `VERITAS_CANARY_MIN_TIER`, `VERITAS_CANARY_MIN_CONFIDENCE`, or `VERITAS_CANARY_MAX_FINDINGS` to make the dashboard command exit nonzero when a configured threshold is missed.

GitHub Actions runs smoke canaries weekly through `.github/workflows/canaries.yml`, uploads the dashboard and per-canary reports as artifacts, and can be started manually with `mode=large-smoke`, `mode=verify-fast`, or `mode=verify` when validating a larger release or a plugin behavior change.

Current pinned canaries:

- Rust: `dtolnay/itoa` at `af77385d0daf4d0e949e81f2588be2e44f69f086`
- Rust: `BurntSushi/memchr` at `ff7dca72388ade97ec536f550271fe5acab0a05f`
- Go: `google/uuid` at `2d3c2a9cc518326daf99a383f07c4d3c44317e4d`
- Go: `gorilla/mux` at `db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265`
- Large Rust: `clap-rs/clap` at `8141e110ecee321277e90b4baa22a5baa02813ea`
- Large Go: `gin-gonic/gin` at `5f4f9643258dc2a65e684b63f12c8d543c936c67`
- Large Python: `pallets/click` at `c48021040a50c659b74e24ac2b11c9c9c6620a21`

Update pins deliberately and in their own commit so canary drift is easy to review.
