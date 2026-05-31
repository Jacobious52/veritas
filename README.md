# veritas

`veritas` is a CLI-first adversarial verification harness for AI-written and AI-modified software.

It answers a question ordinary tests often miss:

> Would the current tests catch the kinds of subtle mistakes an AI coding agent is likely to make?

`veritas` maps changed code to verification targets, generates reviewable harnesses, runs scoped tests/fuzz/mutation checks under budgets, writes CI-friendly reports, and produces AI-ready feedback that can be pasted back into a coding agent.

The default path is deterministic and does not call an LLM. An optional bounded external planner hook can be enabled when you want AI-assisted planning while keeping execution scope and budgets controlled by `veritas`.

For large Go repositories, see [`docs/go-productionization-handoff.md`](docs/go-productionization-handoff.md). It records the production-readiness plan, current implementation state, and next agent tasks for making `veritas` useful beyond regular test execution.

## Vision

AI-generated code often looks correct, compiles, and passes existing tests while still violating hidden assumptions, edge cases, invariants, security expectations, or backwards compatibility. `veritas` is intended to distrust generated code and attack assumptions by orchestrating:

- existing tests
- generated unit tests
- property-based tests
- fuzz harnesses
- mutation-test style checks
- coverage feedback
- minimized repro cases

The long-term loop is:

1. Understand the change by inspecting diffs, changed functions, APIs, call paths, usage sites, and tests.
2. Build a verification plan that prioritizes risky code such as parsers, auth, money, permissions, concurrency, serialization, networking, unsafe code, cryptography, migrations, and error handling.
3. Generate verification artifacts such as unit tests, property tests, fuzz harnesses, differential tests, semantic mutation checks, and regression tests.
4. Execute, observe, classify failures, and minimize repro cases.
5. Improve recursively using coverage, fuzzing, killed/surviving mutants, and failing inputs.

## Workspace

```text
crates/
  veritas-cli/
  veritas-core/
  veritas-plugin-api/
  veritas-rust/
  veritas-go/
  veritas-report/
fixtures/
  sample-rust/
  sample-go/
examples/
  rust-invoice/
  go-invoice/
```

## CLI

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
veritas accept-baseline --id <finding-id>
veritas accept-baseline --all
veritas cleanup
veritas cleanup --dry-run
```

## Install

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

## Copy-Paste AI Agent Instructions

Paste this into an AI coding agent working in a repository:

```text
Use veritas as the adversarial verification loop for this change.

Install if needed:
  cargo install --git https://github.com/Jacobious52/veritas veritas-cli --locked

Before editing broadly:
  veritas review-ai
  Read .veritas/ai/change_digest.md and .veritas/ai/agent_feedback.md.

After making code or test changes:
  veritas verify --changed --profile ci

If veritas reports findings:
  1. Use veritas explain <finding-id>.
  2. Prefer adding focused regression tests or fuzz corpus entries before changing production code.
  3. Inspect .veritas/patches/ and .veritas/repros/.
  4. Rerun veritas verify --changed --profile ci.

Do not ignore warning/error findings without explaining why. Only accept a finding baseline with:
  veritas accept-baseline --id <finding-id>

Clean generated artifacts before finalizing unless intentionally committing reviewed artifacts:
  veritas cleanup
```

## v0 Capabilities

Rust plugin:

- detects `Cargo.toml`
- discovers public free functions in `src/**/*.rs` with tree-sitter
- runs `cargo test --all-targets` with configurable jobs, test threads, command timeouts, and optional systemd cgroup limits
- generates simple `proptest` integration tests for public functions with supported primitive/string-like inputs
- writes generated modules under `tests/veritas_generated/` with a Cargo integration-test index at `tests/veritas_generated.rs`
- runs deterministic source-level mutation probes and reports surviving mutants
- ingests `cargo llvm-cov --summary-only` output when enabled and `cargo-llvm-cov` is installed

Go plugin:

- detects `go.mod`
- discovers exported functions in `.go` files with tree-sitter
- uses `go list -json ./...` to scope package test execution when generated artifacts identify target packages
- runs existing Go tests for selected packages plus configurable transitive reverse dependencies, including test-only imports
- generates basic `testing.F` fuzz harnesses for exported functions with supported Go fuzz parameter types
- writes generated files as `veritas_fuzz_test.go`
- distinguishes handwritten fuzz targets from generated `veritas_fuzz_test.go` files
- runs targeted `go test -run=^$ -fuzz=Fuzz -fuzztime=<N>s <package>` for generated and relevant handwritten fuzz targets, capped per package
- runs deterministic tree-sitter scoped mutation probes and reports surviving mutants with assertion suggestions
- applies build tags and per-command timeouts to Go test, fuzz, package graph, coverage, and mutation commands
- writes package-awareness feedback for changed packages, reverse dependencies, tests, and fuzz coverage
- writes machine-readable Go module/package graph data under `.veritas/package_graph/go.json`
- detects multiple `go.mod` roots and runs scoped package commands from the owning module
- ingests scoped `go test -coverprofile=.veritas/go-cover.out <packages>` output after verification

Reporting:

- renders Markdown, JSON, SARIF, and JUnit XML
- includes targets, plan, generated artifacts, commands run, coverage, failures, and suggested next steps
- saves the latest report to `.veritas/report.json`
- SARIF locations use target file and line information when the finding can be mapped to a verification target
- JUnit failure bodies are trimmed for CI log hygiene

Changed-target verification:

- `veritas verify --changed` reads git diff hunks, staged changes, and untracked files
- maps changed Rust/Go lines to discovered function/package targets when line ranges are available
- generates and runs artifacts once per detected language plugin

Recursive feedback:

- `veritas review-ai` writes `.veritas/ai/change_digest.md` and `.veritas/ai/agent_feedback.md` for copy-paste AI coding loops
- writes coverage feedback under `.veritas/feedback/`
- writes mutation feedback when mutants survive
- writes repro summaries under `.veritas/repros/` with minimized input hints when tool output exposes them
- writes candidate verification patch guidance under `.veritas/patches/`
- `veritas promote-repro` writes reviewable promotion notes under `.veritas/promotions/` for saved repro findings
- writes public API signature baselines under `.veritas/baselines/` and reports signature drift on later runs

Cleanup:

- `veritas cleanup --dry-run` lists generated artifacts that would be removed
- `veritas cleanup` removes `.veritas/`, Rust `tests/veritas_generated*` artifacts, and Go `veritas_fuzz_test.go` files
- skips build, VCS, dependency, and vendor directories while searching for package-local generated artifacts

CI output and failure policy:

- `veritas report --format sarif` emits SARIF 2.1.0
- `veritas report --format junit` emits a compact JUnit XML testsuite
- findings carry severity (`info`, `warning`, `error`, or `critical`)
- findings receive stable IDs such as `vts-...`
- `fail_on_findings = true` makes `verify`, `generate`, and `run` exit non-zero for findings that match `[policy]`
- policy can filter by minimum severity, language, artifact kind, and target risk
- `veritas accept-baseline` records accepted finding IDs under `.veritas/baselines/findings.json` for new-findings-only CI behavior

Planner extension:

- deterministic planning is the default
- optional external LLM planning is available through a command hook behind `VerificationPlanner`
- the command receives bounded JSON on stdin, including `project`, `target`, `default_plan`, and `constraints`
- the command may return either a `VerificationPlan` JSON object or `{ "plan": ... }`
- returned plans are constrained to the provided target, allowed strategy list, generated-test policy, and maximum budget
- planner failures fall back to deterministic planning unless `fail_on_error = true`

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
# Linux/systemd host safety valve for large repos:
systemd_scope = false
memory_max = "4G"
cpu_quota = "200%"

[plugins.go]
fuzz_seconds = 10
fuzz_existing = true
coverage_enabled = true
reverse_dependency_depth = 1
max_fuzz_targets = 20
command_timeout_seconds = 120
max_packages = 64
max_mutants = 8
build_tags = []
```

`veritas verify --profile ci` implies `--changed`, disables full coverage, tightens package/fuzz/mutation/time caps, and enables policy-based failure with `error` as the default minimum severity. Warning-only exploratory findings still appear in the report without failing the process unless the policy is configured to fail on warnings.

## Development

Run the full Rust workspace tests:

```bash
cargo test --workspace
```

The Go verification integration test runs `go test` and `go test -fuzz` when the Go toolchain is available. On machines without `go` on `PATH`, that execution check is skipped while Go scanning and deterministic fuzz artifact generation remain testable.

Run the CLI against fixtures:

```bash
cargo run -p veritas-cli -- scan --root fixtures/sample-rust
cargo run -p veritas-cli -- verify --root fixtures/sample-rust --lang rust --target src/lib.rs
cargo run -p veritas-cli -- verify --root fixtures/sample-rust --changed
cargo run -p veritas-cli -- cleanup --root fixtures/sample-rust --dry-run
cargo run -p veritas-cli -- scan --root fixtures/sample-go
cargo run -p veritas-cli -- verify --root fixtures/sample-go --lang go --target .
```

Run the richer test beds:

```bash
cargo test --manifest-path examples/rust-invoice/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-invoice --lang rust --target src/lib.rs
(cd examples/go-invoice && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-invoice --lang go --target .
```

The example projects intentionally contain hidden assumptions while their handwritten tests pass, so they are useful for validating generated property/fuzz artifacts and report output.

## Publishing

The workspace is prepared for crates.io publishing from GitHub Actions.

To publish with an API token:

1. Create a crates.io API token that can publish new crates and updates.
2. Add it to the GitHub repository as `CARGO_REGISTRY_TOKEN`.
3. Run the `Release` workflow manually with `dry_run=true` to package every crate without uploading.
4. Run the workflow with `dry_run=false`, or push a `v0.1.0` style tag, to publish crates in dependency order.

The release script publishes:

```text
veritas-plugin-api
veritas-core
veritas-report
veritas-rust
veritas-go
veritas-cli
```

After the first release exists on crates.io, trusted publishing can be configured per crate in crates.io settings so future CI releases can use GitHub Actions OIDC instead of a long-lived token.

## Known Limitations

- v0 does not call LLM APIs by default; the external planner hook is opt-in.
- Rust generation only handles public free functions with up to two supported primitive/string-like parameters.
- Go fuzz generation handles exported functions with supported primitive fuzz parameter types; other exported functions are still discovered for targeting, mutation, and API baselines.
- Coverage collection is best-effort and depends on local tools (`cargo-llvm-cov` for Rust when enabled, Go toolchain for Go).
- Mutation probes use deterministic AST-scoped operators for branch, nil/error, comparison, return default, and domain-labeled auth, money, parsing, and serialization risks.
- Minimized repro extraction depends on tool output exposing failing inputs.
- Differential checks compare public signatures, not full behavior.
- Generated tests are intentionally conservative scaffolds that must be reviewed before committing.

## Next Engineering Steps

1. Replace signature-only differential checks with old/new behavioral replay for selected APIs.
2. Turn candidate patch guidance into directly applicable source patches for common Rust and Go shapes.
3. Persist and replay concrete minimized fuzz/proptest inputs as committed regression tests.
4. Add typed semantic mutation operators for auth, money, parsing, serialization, permissions, and error handling.
5. Add owner/team metadata and expiry windows to accepted finding baselines.
