# Releasing

`veritas` publishes workspace crates to crates.io from GitHub Actions.

## Crates

Publish order:

```text
veritas-plugin-api
veritas-core
veritas-report
veritas-rust
veritas-go
veritas-cli
```

The order matters because downstream crates depend on the earlier crates.

## GitHub Actions

Workflow:

```text
.github/workflows/release.yml
```

Release script:

```text
scripts/publish-crates.sh
```

Run a package-only validation:

```bash
gh workflow run release.yml --repo Jacobious52/veritas -f dry_run=true --ref main
```

Publish from the workflow:

```bash
gh workflow run release.yml --repo Jacobious52/veritas -f dry_run=false --ref main
```

Publishing also runs on tags matching `v*`.

## Secret

The workflow uses a repository Actions secret:

```text
CARGO_REGISTRY_TOKEN
```

Set it from a local environment file without printing the token:

```bash
gh secret set -f .env --repo Jacobious52/veritas
```

The crates.io account that owns the token must have a verified email address before the first publish.

The release workflow checks that `CARGO_REGISTRY_TOKEN` is present before running `cargo publish`. If the token is present but publishing fails with a verified-email error, fix the crates.io account profile and rerun the workflow; that failure is outside GitHub secret wiring.

## Local Checks

Run before publishing:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
./scripts/publish-crates.sh --dry-run
```

While editing locally, the package dry-run can include uncommitted files:

```bash
VERITAS_RELEASE_ALLOW_DIRTY=1 ./scripts/publish-crates.sh --dry-run
```

The clean dry-run should pass before a release tag or manual publish run.
