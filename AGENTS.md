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
  veritas-report/       # Markdown, SARIF, and JUnit renderers
fixtures/
  sample-rust/          # small integration fixture
  sample-go/            # small integration fixture
examples/
  rust-invoice/         # richer Rust test bed with hidden parser assumptions
  go-invoice/           # richer Go test bed with hidden parser assumptions
docs/                   # durable user, production, AI-agent, architecture, release docs
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
cargo run -p veritas-cli -- cleanup --root fixtures/sample-rust
cargo run -p veritas-cli -- verify --root fixtures/rust-workspace --lang rust --target .
cargo run -p veritas-cli -- cleanup --root fixtures/rust-workspace
cargo run -p veritas-cli -- scan --root fixtures/sample-go
cargo run -p veritas-cli -- verify --root fixtures/sample-go --lang go --target .
cargo run -p veritas-cli -- cleanup --root fixtures/sample-go
cargo run -p veritas-cli -- verify --root fixtures/go-multimodule --lang go --target services/billing/pkg/invoice
cargo run -p veritas-cli -- cleanup --root fixtures/go-multimodule
```

Run example test beds:

```bash
cargo test --manifest-path examples/rust-invoice/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-invoice --lang rust --target src/lib.rs
cargo run -p veritas-cli -- cleanup --root examples/rust-invoice
(cd examples/go-invoice && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-invoice --lang go --target .
cargo run -p veritas-cli -- cleanup --root examples/go-invoice
```

Dogfood `veritas` on itself safely:

```bash
cargo run -p veritas-cli -- verify --root /home/jacob/veritas --lang rust --target .
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
- `explain`, `promote-repro`, `accept-baseline`, and `cleanup` are implemented CLI commands.
- Findings carry stable IDs and severity. Policy can filter by severity, language, artifact kind, and target risk.
- Accepted finding baselines are stored under `.veritas/baselines/findings.json`.
- Rust workspace roots are supported. Rust scans package `src/` directories inside virtual workspaces.
- Rust discovers public free functions and public methods with Tree-sitter, writes symbol graphs, and uses AST spans for mutation probes.
- Rust property generation is intentionally limited to supported public free functions in packages whose manifest mentions `proptest`.
- Rust command execution supports timeouts, `CARGO_BUILD_JOBS`, `RUST_TEST_THREADS`, and optional systemd scope limits.
- Go supports multiple `go.mod` roots, package graphs from `go list -json`, scoped package tests, reverse dependency selection, build tags, handwritten/generated fuzz discovery, fuzz target caps, and AST-scoped mutation probes.
- Generated Go fuzz harnesses skip function names already covered by handwritten fuzz targets in the same package.
- Go writes package awareness, package graph, and symbol graph artifacts.
- Medium confidence fixtures live in `fixtures/rust-workspace` and `fixtures/go-multimodule`.
- Pinned external canaries run through `./scripts/run-canaries.sh smoke` or `./scripts/run-canaries.sh verify`.
- Coverage is best effort. Rust coverage requires `cargo-llvm-cov` and is disabled by default in the root config. Go coverage can be disabled by config or the CI profile.
- GitHub Actions release workflow exists. crates.io publishing uses `CARGO_REGISTRY_TOKEN` and `scripts/publish-crates.sh`.

## Generated Artifacts

`veritas` writes generated verification artifacts to the target project:

- `.veritas/report.json`
- `.veritas/ai/*.md`
- `.veritas/baselines/*.json`
- `.veritas/feedback/*.md`
- `.veritas/mutations/*.txt`
- `.veritas/package_graph/*.json`
- `.veritas/symbol_graph/*.json`
- `.veritas/repros/*.md`
- `.veritas/patches/*.md`
- `.veritas/promotions/*.md`
- Rust generated tests under `tests/veritas_generated*` or package-local equivalents
- Go generated fuzz files such as `veritas_fuzz_test.go`

Treat generated tests as reviewable artifacts, not automatically trusted source.

Use `veritas cleanup` after fixture, example, and dogfood runs unless the generated artifacts are intentionally being reviewed.

## Documentation

- `README.md`: user-facing overview and quick start
- `docs/ai-agents.md`: copy-paste AI agent workflow
- `docs/production.md`: large-repo and CI operating guide
- `docs/architecture.md`: plugin contract and artifact model
- `docs/confidence.md`: fixture tiers, seeded examples, and external canaries
- `docs/releasing.md`: crates.io release workflow

Keep these docs current when behavior changes. Do not reintroduce temporary roadmap docs for completed work; convert durable knowledge into the docs above.
