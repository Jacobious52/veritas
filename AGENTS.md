# AGENTS.md

Guidance for agents working on `veritas`.

## Project

`veritas` is a Rust CLI and plugin architecture for adversarial verification of AI-generated or AI-modified software. It is CLI-first, CI-friendly, and intentionally not an IDE plugin in v0.

Workspace layout:

```text
crates/
  veritas-cli/          # clap CLI, command routing, output selection
  veritas-core/         # orchestration, planning, changed-target discovery, feedback artifacts
  veritas-plugin-api/   # shared traits and report/data model
  veritas-rust/         # Rust project detection, tree-sitter symbols, proptest, cargo test, coverage, mutation
  veritas-go/           # Go project detection, tree-sitter symbols, fuzz harnesses, go test, coverage, mutation
  veritas-report/       # Markdown, SARIF, and JUnit renderers
fixtures/
  sample-rust/          # small integration fixture
  sample-go/            # small integration fixture
examples/
  rust-invoice/         # richer Rust test bed with hidden parser assumptions
  go-invoice/           # richer Go test bed with hidden parser assumptions
```

## Tooling

Installed locally for Jacob:

- Rust/Cargo: already available through `/home/jacob/.cargo/bin`
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

Run fixture checks:

```bash
cargo run -p veritas-cli -- scan --root fixtures/sample-rust
cargo run -p veritas-cli -- verify --root fixtures/sample-rust --lang rust --target src/lib.rs
cargo run -p veritas-cli -- scan --root fixtures/sample-go
cargo run -p veritas-cli -- verify --root fixtures/sample-go --lang go --target .
```

Run example test beds:

```bash
cargo test --manifest-path examples/rust-invoice/Cargo.toml
cargo run -p veritas-cli -- verify --root examples/rust-invoice --lang rust --target src/lib.rs
(cd examples/go-invoice && go test ./...)
cargo run -p veritas-cli -- verify --root examples/go-invoice --lang go --target .
```

Dogfood `veritas` on itself:

```bash
cargo run -p veritas-cli -- verify --root /home/jacob/veritas --lang rust --target .
cargo run -p veritas-cli -- report --root /home/jacob/veritas --format markdown
cargo run -p veritas-cli -- report --root /home/jacob/veritas --format sarif
cargo run -p veritas-cli -- report --root /home/jacob/veritas --format junit
```

## Generated Artifacts

`veritas` writes generated verification artifacts to the target project:

- `.veritas/report.json`
- `.veritas/baselines/*_api.json`
- `.veritas/feedback/*.md`
- `.veritas/repros/*.md`
- `.veritas/mutations/*.txt`
- Rust generated tests under `tests/veritas_generated*` or package-local equivalents
- Go generated fuzz files such as `veritas_fuzz_test.go`

Treat generated tests as reviewable artifacts, not automatically trusted source.

## Current Behavior Notes

- `verify --changed` parses zero-context git diff hunks and maps changed lines to discovered function line ranges when possible.
- Rust workspace roots are supported; the Rust plugin scans package `src/` directories inside virtual workspaces.
- Rust property generation only runs for packages whose manifest mentions `proptest`.
- Coverage is best-effort. `cargo-llvm-cov` is installed, but full workspace coverage can be slow.
- `fail_on_findings = false` by default so exploratory verification can report findings without failing the CLI process.
- The Go example and fixture should now run because Go is installed locally.

## Remaining Tasks

1. Replace signature-only differential checks with old/new behavioral replay for selected public APIs.
2. Turn coverage feedback and surviving mutants into generated assertions automatically.
3. Persist and replay minimized fuzz/proptest inputs as regression tests instead of only writing repro summaries.
4. Add semantic mutation operators for auth, money, parsing, serialization, permissions, and error handling.
5. Add richer CI failure policy controls by severity, target risk, artifact kind, and language.
6. Improve full-workspace coverage performance and timeout handling for `cargo-llvm-cov`.
7. Add Go self-tests that exercise `go test -fuzz` now that Go is installed locally.
8. Add unit tests for changed hunk parsing, SARIF JSON shape, JUnit escaping, and differential baseline comparisons.
9. Add a stable plugin contract for future language plugins, including target signatures, line ranges, generated artifact ownership, and command time budgets.
10. Add explicit cleanup commands for generated artifacts when examples are used in workshops or demos.
