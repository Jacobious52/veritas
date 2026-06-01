# Install Veritas

The shortest path is crates.io:

```bash
cargo install veritas-cli --locked
```

Use the Git repository when you want the latest `main` before a release:

```bash
cargo install --git https://github.com/Jacobious52/veritas veritas-cli --locked
```

Prebuilt release binaries use these asset names when available:

```text
veritas-x86_64-unknown-linux-gnu.tar.gz
veritas-aarch64-unknown-linux-gnu.tar.gz
veritas-x86_64-apple-darwin.tar.gz
veritas-aarch64-apple-darwin.tar.gz
veritas-x86_64-pc-windows-msvc.zip
```

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

Optional language tools:

- Go projects need `go` on `PATH`.
- Python projects need `python3`; coverage feedback needs `python3 -m coverage`.
- Rust coverage needs `cargo-llvm-cov` and should stay disabled on shared machines unless explicitly needed.

For shared runners, prefer changed verification first:

```bash
veritas review-ai
veritas verify --changed --profile ci
veritas score
veritas repair-prompt
```
