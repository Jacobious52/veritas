# veritas

`veritas` is a Tree-sitter testing oracle for AI-written and AI-modified software.

It is a CLI harness for mutation testing, property testing, fuzzing, coverage feedback, corpus replay, differential behavior checks, and evolutionary analysis across Rust, Go, Python, and future Tree-sitter language plugins.

It answers the question ordinary test runs often miss:

> Would the current tests catch the subtle mistakes an AI coding agent is likely to make?

`veritas` maps changed code to verification targets, generates reviewable harnesses, runs scoped tests under budgets, and writes CI-friendly reports plus AI-ready repair prompts.

The default path is deterministic and does not call an LLM. An optional external planner hook can be enabled for AI-assisted planning while `veritas` still owns execution scope, budgets, and artifact writes.

Project site: [Jacobious52.github.io/veritas](https://jacobious52.github.io/veritas/)

## Why It Feels Different

- It gives an AI agent a concrete next-test queue instead of a vague "add more tests" warning.
- It keeps generated tests reviewable and removable through `.veritas/` artifacts and `veritas cleanup`.
- It is built around a generic plugin contract: Rust, Go, and Python work today, and future languages can reuse the same reports through Tree-sitter symbols, line ranges, command budgets, mutation campaigns, replay, and scoring.
- It is designed for bigger repos: changed-target selection, package/workspace awareness, command budgets, optional Rust cgroup/systemd limits, phase timing telemetry, CI profiles, benchmark fixtures, and external canaries.

## Install

From crates.io:

```bash
cargo install veritas-cli --locked
```

From the Git repository:

```bash
cargo install --git https://github.com/Jacobious52/veritas veritas-cli --locked
```

From GitHub Releases:

Prebuilt binaries are published with release tags when available. Until your platform has a binary asset, use the crates.io or git install path above.

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

# Python verification
python3 --version
python3 -m coverage --version

# Rust coverage, only used when coverage_enabled = true
cargo install cargo-llvm-cov
```

## Quick Start

Use `veritas` on a changed branch:

```bash
veritas review-ai
veritas verify --changed --profile ci
veritas score
veritas repair-prompt
veritas report --format markdown
```

Verify a specific target:

```bash
veritas verify --lang rust --target src/lib.rs
veritas verify --lang go --target ./pkg/invoice
veritas verify --lang python --target invoice.py
```

Explain and promote findings:

```bash
veritas explain <finding-id>
veritas promote-repro --dry-run
veritas evolve --dry-run
veritas evolve --index 0
veritas evolve --index 0 --evaluate
veritas replay-corpus --dry-run
veritas accept-quality-baseline
veritas accept-baseline --id <finding-id>
veritas cleanup
```

What a useful run looks like:

```text
mutation survived: refund_cents <= available_cents -> refund_cents < available_cents
fuzz seed saved: " 12.34 " reproduced parser drift
replay drift: AuthorizeRefund("support", 500) changed behavior
next agent step: promote assertion candidate, rerun, keep only if the mutant dies
```

## Documentation

- [AI Agent Guide](docs/ai-agents.md): copy-paste instructions and review loop for coding agents.
- [Install Guide](docs/install.md): cargo, git, release binary, and GitHub Actions setup.
- [AI Verification Loops](docs/ai-verification-loops.md): tangible Rust, Go, Python, and agent-loop examples.
- [Project Site](docs/index.html): GitHub Pages landing page and public overview.
- [Evolution Demo](docs/evolution.md): real before/candidate/after loop from the Go evolution fixture.
- [Production Guide](docs/production.md): large-repo Go/Rust operation, budgets, CI policy, and host safety.
- [Architecture](docs/architecture.md): workspace layout, plugin contract, artifacts, and planner model.
- [Plugin SDK](docs/plugin-sdk.md): language plugin contract and the Python plugin path.
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
veritas verify --lang python --target path/to/file.py
veritas generate --kind property --target path
veritas generate --kind fuzz --target path
veritas run
veritas report --format markdown
veritas report --format sarif
veritas report --format junit
veritas score
veritas accept-quality-baseline
veritas replay-corpus
veritas repair-prompt
veritas explain <finding-id>
veritas promote-repro
veritas promote-repro --index 0
veritas promote-regression
veritas promote-regression --index 0
veritas evolve --dry-run
veritas evolve --index 0
veritas evolve --all-selected
veritas evolve --all-selected --evaluate
veritas accept-baseline --id <finding-id>
veritas accept-baseline --all
veritas bench --root examples
veritas bench --root examples --format json
veritas cleanup
veritas cleanup --dry-run
```

## Capabilities

Language and plugin model:

- Rust, Go, and Python plugins are available today
- Tree-sitter discovery provides symbols, methods, line ranges, and risk surfaces where grammars support them
- each plugin owns language-specific discovery, generated artifacts, command execution, coverage, replay compilation, and mutation operators
- the core owns shared scoring, policy, replay manifests/results, baselines, corpus entries, mutation campaign records, evolution suites, SARIF/JUnit/Markdown rendering, and AI repair prompts
- future language plugins can add their own Tree-sitter grammar and map into the same target/report/artifact contract

Changed-target verification:

- reads git diffs, staged changes, and untracked files
- maps changed lines to discovered Rust/Go/Python symbols when line ranges are available
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
- runs AST-scoped mutation probes for comparisons, nil/error branches, return defaults, boolean connectors, arithmetic and bitwise operators, assignment operators, increment/decrement statements, unary negation, loop control, literal flips, self-assignments, and domain-labeled risk surfaces
- writes package graph, package-awareness, and symbol graph artifacts

Python verification:

- detects Python projects through `pyproject.toml` or Python source roots
- discovers functions with Tree-sitter and emits symbol graph artifacts
- runs `python3 -m pytest -q` when the project prefers pytest and it is installed, otherwise falls back to `python3 -m unittest discover`
- collects coverage through `coverage.py` when enabled
- runs executable source-range mutation checks for supported comparisons, boolean connectors, and default returns
- supports replay cases for primitive single-argument and multi-argument public functions

Reports and artifacts:

- renders Markdown, JSON, SARIF 2.1.0, and compact JUnit XML
- saves the latest report to `.veritas/report.json`
- runs benchmark suites from `veritas-bench.toml` in temporary project copies and scores expected findings, commands, thresholds, and metrics
- reports mutation score attribution/trends, per-mutant campaign records, assertion candidates, corpus entries/replay, differential replay cases, budget skips/timeouts, property-test strength, fuzz execution, and persisted repro counts in `.veritas/report.json`
- summarizes current confidence and baseline deltas with `veritas score`
- writes API signature baselines and accepted finding baselines
- writes coverage feedback, mutation feedback, assertion candidates, corpus entries, replay manifests/results, budget plans, mutation trend JSON, mutation campaign JSON, evolutionary candidate suites and generation outcomes with fitness/selection signals, repro notes, candidate verification patches, regression notes, evolution plans, promoted regression scaffolds, and promotion notes
- cleans generated artifacts with `veritas cleanup`

Scale and performance posture:

- changed branches are verified before full-repo sweeps; `--changed` is the default CI profile path
- Go package graphs and Rust workspace discovery keep command scope close to the edited surface
- command budgets, fuzz caps, mutation caps, package caps, and policy filters are configurable per repo
- Rust test and coverage commands can run inside systemd scopes with CPU and memory limits on shared hosts
- every report records phase timings for discovery, generation, test execution, coverage, replay, synthesis, and total runtime
- benchmark suites and external canaries track whether Veritas still works beyond tiny fixtures
- near-term performance goals are plugin-safe concurrency, cacheable symbol/package graphs, adaptive mutation sampling, and reusable corpus/baseline data across runs

CI behavior:

- `.github/workflows/ci.yml` runs format, workspace tests, clippy, and Rust/Go/Python fixture scan/verify smoke checks on pull requests and pushes to `main`
- `veritas verify --profile ci` implies `--changed`
- CI profile disables full coverage, tightens package/fuzz/mutation/time caps, and enables policy-based failure on error severity by default
- policy filters can select severity, language, artifact kind, and target risk
- accepted finding IDs support new-findings-only CI behavior

Consumer GitHub Actions starter:

```yaml
name: Veritas
on: [pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install veritas-cli --locked
      - run: veritas verify --changed --profile ci
      - run: veritas repair-prompt --github-step-summary
        if: always()
```

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
min_mutation_score = 70
min_mutation_efficacy = 70
min_mutant_coverage = 80

[mutation]
# Shared by language plugins. Operator names are intentionally generic so
# future Tree-sitter plugins can map their own AST mutations onto the same
# campaign/report model.
enabled_operators = []
disabled_operators = []
exclude_paths = []
dry_run = false
workers = 1 # Rust/Go use isolated temp roots when workers > 1; keep small repos serial by default
test_cpu = 1
timeout_coefficient = 0
output_statuses = [] # e.g. ["lived", "not_covered", "timed_out"]

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
cargo test --manifest-path examples/rust-risk-suite/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-risk-suite --lang rust --target src/lib.rs
(cd examples/go-risk-suite && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-risk-suite --lang go --target .
cargo run -p veritas-cli -- --root examples bench
cargo run -p veritas-cli -- --root examples bench --format json
```

The example projects intentionally contain hidden assumptions while their handwritten tests pass, so they are useful for validating generated property/fuzz artifacts and report output.

Run the concrete evolution demo:

```bash
cargo run -p veritas-cli -- --root examples/go-evolution-loop verify --lang go --target .
cargo run -p veritas-cli -- --root examples/go-evolution-loop score
cargo run -p veritas-cli -- --root examples/go-evolution-loop evolve --dry-run
```

The seeded fixture starts with `14` evolution candidates, `12` selected candidates, `4` surviving mutants, and a `55` confidence score. Promoting the top `ParseInvoiceTotal` candidate into owned assertions raises the mutation score from `58%` to `91%`, removes the surviving mutants, and raises the confidence score to `98`. See [docs/evolution.md](docs/evolution.md) for the exact before/candidate/after commands and artifact paths.

Run external canary smoke checks when you want confidence against real pinned repositories:

```bash
./scripts/run-canaries.sh smoke
./scripts/run-canaries.sh verify-fast
./scripts/run-canaries.sh verify
```

The same canaries run weekly in GitHub Actions and can be started manually from the `External Canaries` workflow. Each run writes `target/external-fixtures/reports/canary-dashboard.md` with scan/verify tiers and trend deltas. Set `VERITAS_CANARY_MIN_TIER`, `VERITAS_CANARY_MIN_CONFIDENCE`, or `VERITAS_CANARY_MAX_FINDINGS` when a canary dashboard should fail CI on a missed threshold.
