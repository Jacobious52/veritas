# AGENTS.md

Guidance for agents working on `veritas`.

## Project

`veritas` is a Rust CLI and plugin architecture for adversarial verification of AI-generated or AI-modified software. It is CLI-first, CI-friendly, deterministic by default, and focused on changed-scope verification rather than IDE integration.

Workspace layout:

```text
crates/
  veritas-cli/          # clap CLI, command routing, output selection
  veritas-core/         # orchestration, planning, changed targets, artifacts, policy
  veritas-plugin-api/   # shared traits and report/data model
  veritas-rust/         # Rust detection, Tree-sitter symbols, proptest, cargo, coverage, mutation
  veritas-go/           # Go detection, Tree-sitter symbols, fuzzing, go test, coverage, mutation
  veritas-python/       # Python detection, Tree-sitter symbols, pytest/unittest, coverage, mutation
  veritas-report/       # Markdown, SARIF, and JUnit renderers
fixtures/
  sample-rust/          # small integration fixture
  sample-go/            # small integration fixture
examples/
  rust-invoice/         # richer Rust test bed with hidden parser assumptions
  go-invoice/           # richer Go test bed with hidden parser assumptions
  rust-commerce/        # seeded commerce benchmark for parsing, refunds, coupons, permissions
  go-api-service/       # seeded API benchmark for parsing, tokens, status, authorization
  rust-mutation-score/  # seeded Rust benchmark with killed and surviving mutants
  go-mutation-score/    # seeded Go benchmark with killed and surviving mutants
  rust-risk-suite/      # broader Rust risk benchmark for auth, money, parsing, serialization
  go-risk-suite/        # broader Go risk benchmark for fuzzing and mutation attribution
  rust-concurrency-db/  # advanced Rust mutation fixture for locks, transactions, retries, threads
  go-concurrency-db/    # advanced Go mutation fixture for goroutines, locks, transactions, retries
  veritas-bench.toml    # benchmark manifest of expected detections
docs/                   # durable docs plus GitHub Pages landing page
scripts/run-canaries.sh # pinned external repo smoke/verify checks
```

## Tooling

Installed locally for Jacob:

- Rust/Cargo: available through `/home/jacob/.cargo/bin`
- Go: `/home/jacob/.local/bin/go` -> `/home/jacob/.local/go/bin/go`
- `cargo-llvm-cov`: `/home/jacob/.cargo/bin/cargo-llvm-cov`

`/home/jacob/.local/bin` and `/home/jacob/.cargo/bin` are expected to be on `PATH`.

## Common Commands

Run the main workspace checks:

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run package-release validation:

```bash
./scripts/publish-crates.sh --dry-run
```

While editing locally, use:

```bash
VERITAS_RELEASE_ALLOW_DIRTY=1 ./scripts/publish-crates.sh --dry-run
```

Run fixture checks:

```bash
cargo run -p veritas-cli -- scan --root fixtures/sample-rust
cargo run -p veritas-cli -- verify --root fixtures/sample-rust --lang rust --target src/lib.rs
cargo run -p veritas-cli -- conformance --root fixtures/sample-rust
cargo run -p veritas-cli -- cleanup --root fixtures/sample-rust
cargo run -p veritas-cli -- verify --root fixtures/rust-workspace --lang rust --target .
cargo run -p veritas-cli -- cleanup --root fixtures/rust-workspace
cargo run -p veritas-cli -- scan --root fixtures/sample-go
cargo run -p veritas-cli -- verify --root fixtures/sample-go --lang go --target .
cargo run -p veritas-cli -- conformance --root fixtures/sample-go
cargo run -p veritas-cli -- cleanup --root fixtures/sample-go
cargo run -p veritas-cli -- verify --root fixtures/go-multimodule --lang go --target services/billing/pkg/invoice
cargo run -p veritas-cli -- cleanup --root fixtures/go-multimodule
cargo run -p veritas-cli -- scan --root fixtures/sample-python
cargo run -p veritas-cli -- verify --root fixtures/sample-python --lang python --target invoice.py
cargo run -p veritas-cli -- conformance --root fixtures/sample-python
cargo run -p veritas-cli -- cleanup --root fixtures/sample-python
```

Run example test beds:

```bash
cargo test --manifest-path examples/rust-invoice/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-invoice --lang rust --target src/lib.rs
cargo run -p veritas-cli -- cleanup --root examples/rust-invoice
(cd examples/go-invoice && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-invoice --lang go --target .
cargo run -p veritas-cli -- cleanup --root examples/go-invoice
cargo test --manifest-path examples/rust-concurrency-db/Cargo.toml
(cd examples/go-concurrency-db && go test ./...)
cargo run -p veritas-cli -- --root examples/rust-concurrency-db mutants list --lang rust --target src/lib.rs --diffs
cargo run -p veritas-cli -- --root examples/go-concurrency-db mutants list --lang go --target . --diffs
cargo run -p veritas-cli -- --root examples/rust-concurrency-db mutants run --lang rust --target src/lib.rs --from-campaign .veritas/mutations/rust_campaign.json --status lived
cargo run -p veritas-cli -- --root examples bench
```

Dogfood `veritas` on itself safely:

```bash
cargo run -p veritas-cli -- verify --root /home/jacob/veritas --lang rust --target .
cargo run -p veritas-cli -- score --root /home/jacob/veritas
cargo run -p veritas-cli -- replay-corpus --root /home/jacob/veritas --dry-run
cargo run -p veritas-cli -- report --root /home/jacob/veritas --format markdown
cargo run -p veritas-cli -- report --root /home/jacob/veritas --format sarif
cargo run -p veritas-cli -- report --root /home/jacob/veritas --format junit
cargo run -p veritas-cli -- cleanup --root /home/jacob/veritas
```

The root `veritas.toml` enables Rust systemd scope limits for local safety.
Full-repo dogfood also traverses `examples/rust-invoice`, which intentionally exposes a generated property-test finding for `parse_invoice_total`. That finding is useful for checking repro/report output; clean generated artifacts afterward.

## Current State

- `verify --changed` parses git diff hunks, staged changes, and untracked files, then maps changed lines to discovered target line ranges when possible.
- `review-ai` writes AI digest and feedback artifacts under `.veritas/ai/`.
- `explain`, `promote-repro`, `promote-regression`, `evolve`, `accept-baseline`, and `cleanup` are implemented CLI commands.
- Findings carry stable IDs and severity. Policy can filter by severity, language, artifact kind, and target risk.
- Accepted finding baselines are stored under `.veritas/baselines/findings.json`.
- Rust workspace roots are supported. Rust scans package `src/` directories inside virtual workspaces.
- Rust discovers public free functions and public methods with Tree-sitter, writes symbol graphs, and uses AST spans for mutation probes.
- Rust property generation is intentionally limited to supported public free functions in packages whose manifest mentions `proptest`.
- Rust command execution supports timeouts, `CARGO_BUILD_JOBS`, `RUST_TEST_THREADS`, and optional systemd scope limits.
- Go supports multiple `go.mod` roots, package graphs from `go list -json`, scoped package tests, reverse dependency selection, build tags, handwritten/generated fuzz discovery, bounded concurrent fuzz targets, isolated parallel mutation workers, and AST-scoped mutation probes.
- `veritas bench` runs seeded examples in temporary copies and scores expected finding, artifact, command, threshold, mutation attribution, mutation worker/isolation, property strength, corpus, replay, and budget metrics from `veritas-bench.toml`.
- `veritas mutants list` previews candidate mutants without executing native tests. It supports Markdown/JSON output, diff previews, domain/operator/path/symbol filters, and validated shard selection. Integration coverage proves shard unions match the unsharded candidate set without duplicate mutant IDs. `veritas mutants run --from-campaign ... --status lived` focuses reruns on previous survivors by stable mutant ID, and `veritas mutants merge` combines shard campaign artifacts.
- Reports include first-class quality metrics for mutation score/trends, property strength, generated-test failures, fuzz execution, corpus replay, and persisted repros.
- `veritas score` reads `.veritas/report.json` and summarizes confidence from mutation score, findings, assertion candidates, corpus entries/replay, replay cases, baseline deltas, and budget health.
- `veritas accept-quality-baseline` stores `.veritas/baselines/quality.json` after a reviewed good state.
- `veritas conformance` checks the generic plugin contract for stable IDs, source-relative paths, function symbols, line ranges, and existing target files.
- `veritas next --explain` ranks active findings and selected evolution candidates into one AI-ready next-action queue with estimated confidence impact.
- `veritas score --mode all` prints current, strict, and verified anti-gaming confidence views.
- `veritas review-packet` writes `.veritas/review/query.json` and `.veritas/review/prompt.md` for blind agent review across naming, abstractions, boundaries, error handling, testability, and security.
- `veritas agent-instructions --agent codex` writes `.veritas/ai/veritas_agent_instructions.md` with the proof loop and anti-gaming rules.
- `veritas badge` writes `.veritas/badge.svg` with confidence grade and mutation score for README/Pages use.
- Observation artifacts now include structured `.veritas/cache/*_targets.json`, `.veritas/assertions/*.json`, `.veritas/corpus/*.json`, `.veritas/corpus/replay_result.json`, `.veritas/differential/*_result.json`, `.veritas/budgets/*.json`, `.veritas/trends/*.json`, `.veritas/mutations/*_campaign.json`, and `.veritas/evolution/*_candidates.json` plus `*_suite.json` to help AI agents close the verification loop.
- Evolution suites are plugin-neutral ranked queues. `veritas evolve --dry-run` inspects them, while `veritas evolve --index <n> --evaluate` and `--all-selected --evaluate` apply safe selected candidates as reviewable artifacts or language-owned regression scaffolds, rerun scoped verification, write `.veritas/evolution/*_evaluation_*.md`, and remove generated candidate files when the evaluated report regresses or cannot be evaluated.
- Mutation probes cover comparisons, equality/nil branches, boolean connectors, arithmetic/bitwise/assignment operators, loop/literal/default mutations, async/task lifecycle, lock/defer/atomic synchronization, transaction/rollback/isolation/tenant/idempotency database surfaces, retry/backoff/transient-error behavior, testability seams, and brittleness/equivalence probes where the active language plugin can detect them.
- Rust, Go, and Python mutations emit generic campaign records with `runnable`, `not_covered`, `killed`, `lived`, `timed_out`, and `not_viable` statuses for downstream AI repair loops. Records include source spans, replacements, diff previews, risk notes, suggested tests, skip reasons, selected commands, and shared domain/operator taxonomy. Shared mutation config supports domain/operator allow/deny lists, include/exclude path and symbol filters, dry-run discovery, timeout floors/caps/multipliers, sharding, campaign status filtering, worker counts, and isolated-copy exclusions. Rust and Go use isolated temporary project roots when `workers > 1`; `workers = 1` preserves source-rewrite serial behavior as a troubleshooting fallback. Reports include requested/effective workers, isolation failures, isolated-copy setup/copy milliseconds, exclusion summaries, per-worker copy records, and scratch roots on copy failure.
- Differential mode writes both API signature baselines and `.veritas/differential/*_replay.json` behavior replay manifests.
- Differential behavior replay is batched through the plugin contract with `replay_behaviors`; `replay_behavior` is the compatibility fallback for future plugins.
- Surviving mutants, minimized fuzz/proptest inputs, and generated-harness failures produce `.veritas/regressions/*.md` assertion guidance.
- `promote-regression` asks language plugins to create package-owned regression test scaffolds. Rust writes ignored `tests/veritas_regression_*.rs` tests; Go writes skipped `veritas_regression_*_test.go` tests.
- Generated Go fuzz harnesses skip function names already covered by handwritten fuzz targets in the same package.
- Go writes package awareness, package graph, and symbol graph artifacts.
- Medium confidence fixtures live in `fixtures/rust-workspace` and `fixtures/go-multimodule`.
- Python supports Tree-sitter target discovery, symbol graphs, pytest detection with unittest fallback, Hypothesis property candidate execution when `hypothesis` and `pytest` are installed, coverage.py summaries, executable simple mutation checks, and batched primitive free-function replay.
- Pinned external canaries run through `./scripts/run-canaries.sh smoke`, `./scripts/run-canaries.sh verify-fast`, or `./scripts/run-canaries.sh verify`.
- GitHub Actions runs weekly smoke canaries and supports manual smoke/verify-fast/verify canary runs.
- Main CI lives at `.github/workflows/ci.yml` and runs format, workspace tests, clippy, and Rust/Go/Python fixture smoke verification.
- Coverage is best effort. Rust coverage requires `cargo-llvm-cov` and is disabled by default in the root config. Go coverage can be disabled by config or the CI profile.
- GitHub Actions release workflow exists. crates.io publishing uses `CARGO_REGISTRY_TOKEN` and `scripts/publish-crates.sh`.

## Generated Artifacts

`veritas` writes generated verification artifacts to the target project:

- `.veritas/report.json`
- `.veritas/badge.svg`
- `.veritas/ai/*.md`
- `.veritas/review/*.json`
- `.veritas/review/*.md`
- `.veritas/baselines/*.json`
- `.veritas/cache/*.json`
- `.veritas/assertions/*.json`
- `.veritas/corpus/*.json`
- `.veritas/corpus/replay_result.json`
- `.veritas/differential/*.json`
- `.veritas/budgets/*.json`
- `.veritas/trends/*.json`
- `.veritas/feedback/*.md`
- `.veritas/mutations/*.txt`
- `.veritas/mutations/*_campaign.json`
- `.veritas/mutations/*_progress.md`
- `.veritas/mutations/*_progress.live.md`
- `.veritas/mutations/runs/*/{records,diffs,logs}/*`
- `.veritas/package_graph/*.json`
- `.veritas/symbol_graph/*.json`
- `.veritas/repros/*.md`
- `.veritas/patches/*.md`
- `.veritas/regressions/*.md`
- `.veritas/evolution/*.md`
- `.veritas/evolution/*_candidates.json`
- `.veritas/evolution/*_suite.json`
- `.veritas/evolution/*_evaluation_*.md`
- `.veritas/evolution/*_generation_*.json`
- `.veritas/promotions/*.md`
- Rust generated tests under `tests/veritas_generated*` or package-local equivalents
- Rust promoted regression scaffolds under `tests/veritas_regression_*.rs` or package-local equivalents
- Go generated fuzz files such as `veritas_fuzz_test.go`
- Go promoted regression scaffolds such as `veritas_regression_*_test.go`

Treat generated tests as reviewable artifacts, not automatically trusted source.

Use `veritas cleanup` after fixture, example, and dogfood runs unless the generated artifacts are intentionally being reviewed.

## Documentation

- `README.md`: user-facing overview and quick start
- `docs/ai-agents.md`: copy-paste AI agent workflow
- `docs/ai-verification-loops.md`: concrete Rust, Go, Python, and AI repair-loop examples
- `docs/production.md`: large-repo and CI operating guide
- `docs/architecture.md`: plugin contract and artifact model
- `docs/confidence.md`: fixture tiers, seeded examples, and external canaries
- `docs/releasing.md`: crates.io release workflow
- `docs/index.html`: GitHub Pages landing page

Keep these docs current when behavior changes. Do not reintroduce temporary roadmap docs for completed work; convert durable knowledge into the docs above.
