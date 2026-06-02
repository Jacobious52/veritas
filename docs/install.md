# Install Veritas

The shortest path is the prebuilt GitHub Release binary:

```bash
curl -fsSL https://github.com/Jacobious52/veritas/releases/latest/download/install.sh | sh
```

Install into a custom directory:

```bash
curl -fsSL https://github.com/Jacobious52/veritas/releases/latest/download/install.sh | INSTALL_DIR="$HOME/bin" sh
```

Install a specific tag:

```bash
curl -fsSL https://github.com/Jacobious52/veritas/releases/latest/download/install.sh | VERSION=v0.1.1 sh
```

Use crates.io when you prefer building locally:

```bash
cargo install veritas-cli --locked
```

Bootstrap a repository after install:

```bash
veritas init --ci --agent-instructions
```

That writes `.veritas.toml`, a starter GitHub Actions workflow, and copy-paste AI agent instructions under `.veritas/ai/`. Existing files are not overwritten unless `--force` is passed. Preview first with:

```bash
veritas init --ci --agent-instructions --dry-run
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
veritas-checksums.txt
install.sh
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
      - run: curl -fsSL https://github.com/Jacobious52/veritas/releases/latest/download/install.sh | sh
      - run: veritas verify --changed --profile ci
      - run: veritas repair-prompt --github-step-summary
        if: always()
```

Local action shortcut:

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
      - uses: Jacobious52/veritas/.github/actions/veritas@main
        with:
          args: verify --changed --profile ci
          repair-prompt: "true"
```

Optional language tools:

- Go projects need `go` on `PATH`.
- Python projects need `python3`; coverage feedback needs `python3 -m coverage`.
- TypeScript/JavaScript projects use Bun, npm, pnpm, or Yarn test scripts for baseline and mutation runs. Veritas-generated TS/JS probes and coverage use Bun when available; scans and symbol artifacts still work when Bun is not installed.
- Rust coverage needs `cargo-llvm-cov` and should stay disabled on shared machines unless explicitly needed.

For shared runners, prefer changed verification first:

```bash
veritas review-ai
veritas verify --changed --profile ci
veritas score
veritas repair-prompt
```
