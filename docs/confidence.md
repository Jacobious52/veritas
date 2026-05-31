# Confidence Guide

`veritas` uses several layers of confidence checks. Keep fast checks in normal development and reserve external canaries for manual or scheduled runs.

## Local Test Layers

1. Unit tests in each crate cover parser helpers, report rendering, changed-target selection, cleanup, package scoping, mutation candidates, and artifact rendering.
2. Tiny fixtures in `fixtures/sample-rust` and `fixtures/sample-go` keep the CLI smoke path fast.
3. Medium fixtures exercise production shapes:
   - `fixtures/rust-workspace`: virtual Cargo workspace, multiple packages, public free functions, public methods, package-local generated proptests, and mutation feedback.
   - `fixtures/go-multimodule`: two Go modules, cross-module imports, reverse dependency scoping, handwritten fuzz discovery, generated fuzz suppression for duplicate names, package graph artifacts, and symbol graphs.
4. Seeded examples in `examples/rust-invoice` and `examples/go-invoice` intentionally pass handwritten tests while generated verification exposes parser assumptions.

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

## External Canaries

External canaries clone pinned public repositories into `target/external-fixtures`:

```bash
./scripts/run-canaries.sh smoke
./scripts/run-canaries.sh verify
```

Smoke mode only scans. Verify mode runs `veritas verify --target .` and then cleans generated artifacts.

Current pinned canaries:

- Rust: `dtolnay/itoa` at `af77385d0daf4d0e949e81f2588be2e44f69f086`
- Go: `google/uuid` at `2d3c2a9cc518326daf99a383f07c4d3c44317e4d`

Update pins deliberately and in their own commit so canary drift is easy to review.
