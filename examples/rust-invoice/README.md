# Rust Invoice Test Bed

This is a deliberately small Rust project for dogfooding `veritas`.

The handwritten tests pass, but `parse_invoice_total` encodes hidden assumptions with `expect`, so generated property tests should expose panic paths for malformed invoice strings.

Run:

```bash
cargo test
cargo run -p veritas-cli -- verify --root examples/rust-invoice --lang rust --target src/lib.rs
```
