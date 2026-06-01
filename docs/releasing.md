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

## Release Binaries

Release tags are the home for prebuilt CLI binaries. When binary packaging is enabled for a platform, attach assets to the GitHub Release for that tag using names like:

```text
veritas-x86_64-unknown-linux-gnu.tar.gz
veritas-aarch64-apple-darwin.tar.gz
veritas-x86_64-pc-windows-msvc.zip
```

Until a platform has an attached binary, users should install with:

```bash
cargo install veritas-cli --locked
```

or:

```bash
cargo install --git https://github.com/Jacobious52/veritas veritas-cli --locked
```

The publish script is resumable: it skips crate versions that already exist on crates.io and retries once after short crates.io rate-limit responses. If a first workspace release partially succeeds, rerun the failed workflow after the crates.io retry time instead of changing the published artifacts.

After any successful publish, bump the workspace package version and internal crate dependency versions before landing new feature work.

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

The validate job also installs `veritas-cli` from the checked-out workspace and runs a fixture scan. This catches broken install metadata before publishing starts.

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
