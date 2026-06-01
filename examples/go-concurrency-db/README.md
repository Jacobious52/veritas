# go-concurrency-db

Seeded Go fixture for advanced mutation operators around goroutine lifecycle,
deferred unlocks, tenant-scoped queries, idempotency, transaction commit/rollback,
retry/backoff behavior, and atomic commit counters.

```bash
(cd examples/go-concurrency-db && go test ./...)
cargo run -p veritas-cli -- mutants list --root examples/go-concurrency-db --lang go --target . --diffs
```
