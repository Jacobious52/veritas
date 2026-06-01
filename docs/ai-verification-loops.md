# AI Verification Loops

These examples show what an AI-driven verification pass looks like in practice. The loop is always the same: discover risky targets, run bounded adversarial checks, turn findings into owned tests or seeds, then score the next state.

## Changed Code Loop

```bash
veritas review-ai
veritas verify --changed --profile ci
veritas score
```

The agent reads `.veritas/ai/change_digest.md` to see changed files and target symbols. It reads `.veritas/ai/agent_feedback.md` for the next verification command and artifact checklist. A good follow-up is a small owned regression test, not a broad rewrite.

## Rust: Mutation Plus Properties

Example target:

```rust
pub fn parse_invoice_total(raw: &str) -> Option<i64> {
    let cents = raw.trim().replace('_', "").parse::<i64>().ok()?;
    (0..=1_000_000).contains(&cents).then_some(cents)
}
```

Run:

```bash
veritas verify --lang rust --target src/lib.rs
veritas evolve --dry-run
```

Useful artifacts:

- `tests/veritas_generated/src_lib_rs_target.rs`: reviewable proptest scaffold when the crate supports `proptest`
- `.veritas/mutations/*_campaign.json`: killed, lived, timed-out, not-viable, and not-covered mutants
- `.veritas/assertions/*.json`: assertion candidates such as boundary values around `1_000_000`
- `.veritas/evolution/*_suite.json`: ranked next tests to add

Agent action: promote a surviving boundary mutant into a handwritten assertion for `1_000_001`, rerun `veritas verify`, then keep the test only if mutation score and `veritas score` improve.

## Go: Fuzzing Plus Mutation

Example target:

```go
func ParseInvoiceTotal(raw string) (int, bool) {
    normalized := strings.ReplaceAll(strings.TrimSpace(raw), "_", "")
    cents, err := strconv.Atoi(normalized)
    if err != nil || cents > 1_000_000 {
        return 0, false
    }
    return cents, true
}
```

Run:

```bash
veritas verify --lang go --target .
veritas replay-corpus --dry-run
```

Useful artifacts:

- `veritas_fuzz_test.go`: generated fuzz harness with edge-case seed rows
- `.veritas/package_graph/go.json`: module/package/test/fuzz ownership and reverse dependencies
- `.veritas/corpus/*.json`: persisted fuzz or repro seed metadata
- `.veritas/regressions/*.md`: concise guidance for turning a finding into an owned test

Agent action: copy the smallest repro input into a package-owned Go test or fuzz seed, run `go test ./...`, then rerun `veritas verify`.

## Python: Plugin Contract

Example target:

```python
def normalize_discount_code(raw: str) -> str:
    return raw.strip().replace("-", "").upper()
```

Run:

```bash
veritas scan
veritas verify --lang python --target sample_python/pricing.py
```

Useful artifacts:

- `.veritas/symbols/python_*.json`: Tree-sitter function/method symbols, signatures, line ranges, risks, and calls
- `.veritas/mutations/python_*.json`: mutation target/operator manifest for future executable Python mutation workers
- `.veritas/differential/python_result.json`: batched behavior replay observations or stable fallback fingerprints

Agent action: use the symbol graph and mutation manifest to choose precise tests before editing production code. Python currently runs pytest when the project prefers pytest and it is installed; otherwise it falls back to `python3 -m unittest discover`.

## Snapshot: Verification To Repair

```text
Finding: mutation survived in Go function `ParseInvoiceTotal`
Artifact: .veritas/mutations/go_campaign.json
Candidate: Add the smallest assertion that fails under this surviving mutant.
Agent patch: add TestParseInvoiceTotalRejectsHugeValues
Check: veritas verify --changed --profile ci
Outcome: surviving mutant becomes killed; confidence score increases
```

That is the intended AI loop: `veritas` supplies scoped evidence, the agent writes owned verification, and the next report proves whether confidence actually improved.
