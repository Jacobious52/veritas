# rust-concurrency-db

Seeded Rust fixture for advanced mutation operators around tenant-scoped writes,
transaction decisions, lock modes, atomic ordering, retry/backoff behavior, and
thread lifecycle joins.

```bash
cargo test --manifest-path examples/rust-concurrency-db/Cargo.toml
cargo run -p veritas-cli -- mutants list --root examples/rust-concurrency-db --lang rust --target src/lib.rs --diffs
```
