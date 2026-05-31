# veritas

`veritas` is a CLI-first adversarial verification harness for AI-written and AI-modified software.

It answers the question ordinary test runs often miss:

> Would the current tests catch the kinds of subtle mistakes an AI coding agent is likely to make?

`veritas` maps changed code to verification targets, generates reviewable harnesses, runs scoped tests, fuzzing, mutation probes, and coverage collection under budgets, then writes CI-friendly reports and AI-ready feedback.

The default path is deterministic and does not call an LLM. An optional external planner hook can be enabled for AI-assisted planning while `veritas` still owns execution scope, budgets, and artifact writes.

## Install

From crates.io:

```bash
cargo install veritas-cli --locked
```

From the Git repository:

```bash
cargo install --git https://github.com/Jacobious52/veritas veritas-cli --locked
```

For local development:

```bash
git clone https://github.com/Jacobious52/veritas.git
cd veritas
cargo build --workspace
cargo run -p veritas-cli -- scan
```

Optional tools:

```bash
# Go verification
go version

# Rust coverage, only used when coverage_enabled = true
cargo install cargo-llvm-cov
```

## Quick Start

Use `veritas` on a changed branch:

```bash
veritas review-ai
veritas verify --changed --profile ci
veritas report --format markdown
```

Verify a specific target:

```bash
veritas verify --lang rust --target src/lib.rs
veritas verify --lang go --target ./pkg/invoice
```

Explain and promote findings:

```bash
veritas explain <finding-id>
veritas promote-repro --dry-run
veritas accept-baseline --id <finding-id>
veritas cleanup
```

## Documentation

- [AI Agent Guide](docs/ai-agents.md): copy-paste instructions and review loop for coding agents.
- [Production Guide](docs/production.md): large-repo Go/Rust operation, budgets, CI policy, and host safety.
- [Architecture](docs/architecture.md): workspace layout, plugin contract, artifacts, and planner model.
- [Confidence Guide](docs/confidence.md): fixture tiers, seeded examples, and external canaries.
- [Releasing](docs/releasing.md): crates.io publishing through GitHub Actions.

## CLI Surface

```bash
veritas scan
veritas review-ai
veritas verify --changed
veritas verify --changed --profile ci
veritas verify --lang rust --target path/to/file.rs
veritas verify --lang go --target ./pkg/foo
veritas generate --kind property --target path
veritas generate --kind fuzz --target path
veritas run
veritas report --format markdown
veritas report --format sarif
veritas report --format junit
veritas explain <finding-id>
veritas promote-repro
veritas promote-repro --index 0
veritas promote-regression
veritas promote-regression --index 0
veritas accept-baseline --id <finding-id>
veritas accept-baseline --all
veritas bench --root examples
veritas bench --root examples --format json
veritas cleanup
veritas cleanup --dry-run
```

## Capabilities

Changed-target verification:

- reads git diffs, staged changes, and untracked files
- maps changed lines to discovered Rust/Go symbols when line ranges are available
- scopes package commands to changed packages and selected reverse dependencies where graph data exists
- writes AI review artifacts with change digests and verification guidance

Rust verification:

- detects packages and virtual workspaces through `Cargo.toml`
- discovers public free functions and public methods with Tree-sitter
- writes package-local `proptest` integration harnesses for supported public free functions, including no-panic and deterministic-output properties where signatures allow them
- runs `cargo test --all-targets` with configurable jobs, test threads, command timeouts, and optional systemd scope limits
- runs AST-scoped mutation probes and reports surviving mutants
- collects `cargo llvm-cov --summary-only` when enabled
- writes Rust symbol graph artifacts under `.veritas/symbol_graph/`

Go verification:

- detects one or more `go.mod` roots
- discovers exported functions and methods with Tree-sitter
- builds package graphs with `go list -json ./...`
- runs scoped `go test` commands for selected packages plus configurable reverse dependencies
- discovers handwritten and generated fuzz targets
- writes `testing.F` fuzz harnesses for exported free functions with supported Go fuzz parameter types and edge-case seed rows
- runs relevant `go test -run=^$ -fuzz=...` targets through a bounded scheduler within caps and timeouts
- applies build tags to Go list, test, fuzz, coverage, and mutation commands
- runs AST-scoped mutation probes for comparisons, nil/error branches, return defaults, boolean connectors, arithmetic operators, and domain-labeled risk surfaces
- writes package graph, package-awareness, and symbol graph artifacts

Reports and artifacts:

- renders Markdown, JSON, SARIF 2.1.0, and compact JUnit XML
- saves the latest report to `.veritas/report.json`
- runs benchmark suites from `veritas-bench.toml` in temporary project copies and scores expected findings, commands, thresholds, and metrics
- reports mutation score, property-test quality, fuzz execution, and persisted repro counts in `.veritas/report.json`
- writes API signature baselines and accepted finding baselines
- writes coverage feedback, mutation feedback, replay manifests, repro notes, candidate verification patches, regression notes, evolution plans, promoted regression scaffolds, and promotion notes
- cleans generated artifacts with `veritas cleanup`

CI behavior:

- `veritas verify --profile ci` implies `--changed`
- CI profile disables full coverage, tightens package/fuzz/mutation/time caps, and enables policy-based failure on error severity by default
- policy filters can select severity, language, artifact kind, and target risk
- accepted finding IDs support new-findings-only CI behavior

## Config

Create `veritas.toml` or `.veritas.toml` in the target repo:

```toml
[veritas]
budget_seconds = 120
write_generated_tests = true
fail_on_generated_test_failure = true
fail_on_findings = false

[planner]
mode = "deterministic"
# mode = "external_llm"
# command = "my-veritas-planner"
# fail_on_error = false

[policy]
fail_on_severity = "error"
fail_on_languages = []
fail_on_artifact_kinds = []
fail_on_target_risks = []

[plugins.rust]
property_framework = "proptest"
command_timeout_seconds = 120
coverage_enabled = false
coverage_timeout_seconds = 120
cargo_jobs = 1
test_threads = 1
systemd_scope = false
memory_max = "4G"
cpu_quota = "200%"

[plugins.go]
fuzz_seconds = 10
fuzz_existing = true
fuzz_concurrency = 2
coverage_enabled = true
reverse_dependency_depth = 1
max_fuzz_targets = 20
command_timeout_seconds = 120
max_packages = 64
max_mutants = 8
build_tags = []
```

For shared machines, keep Rust coverage disabled unless needed and enable systemd scope limits:

```toml
[plugins.rust]
coverage_enabled = false
systemd_scope = true
cargo_jobs = 1
test_threads = 1
memory_max = "4G"
cpu_quota = "200%"
```

## Development

Run the workspace checks:

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run fixture checks:

```bash
cargo run -p veritas-cli -- scan --root fixtures/sample-rust
cargo run -p veritas-cli -- verify --root fixtures/sample-rust --lang rust --target src/lib.rs
cargo run -p veritas-cli -- cleanup --root fixtures/sample-rust --dry-run
cargo run -p veritas-cli -- verify --root fixtures/rust-workspace --lang rust --target .
cargo run -p veritas-cli -- scan --root fixtures/sample-go
cargo run -p veritas-cli -- verify --root fixtures/sample-go --lang go --target .
cargo run -p veritas-cli -- verify --root fixtures/go-multimodule --lang go --target services/billing/pkg/invoice
```

Run the richer example beds:

```bash
cargo test --manifest-path examples/rust-invoice/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-invoice --lang rust --target src/lib.rs
(cd examples/go-invoice && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-invoice --lang go --target .
cargo test --manifest-path examples/rust-commerce/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-commerce --lang rust --target src/lib.rs
(cd examples/go-api-service && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-api-service --lang go --target .
cargo test --manifest-path examples/rust-mutation-score/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-mutation-score --lang rust --target src/lib.rs
(cd examples/go-mutation-score && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-mutation-score --lang go --target .
cargo run -p veritas-cli -- --root examples bench
cargo run -p veritas-cli -- --root examples bench --format json
```

The example projects intentionally contain hidden assumptions while their handwritten tests pass, so they are useful for validating generated property/fuzz artifacts and report output.

Run external canary smoke checks when you want confidence against real pinned repositories:

```bash
./scripts/run-canaries.sh smoke
```

The same canaries run weekly in GitHub Actions and can be started manually from the `External Canaries` workflow.
