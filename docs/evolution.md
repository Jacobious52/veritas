# Evolution Demo

This demo uses `examples/go-evolution-loop`, a small but realistic Go package with refund authorization, invoice parsing, and settlement state logic. The handwritten tests pass, but Veritas finds missing assertions around parser boundaries.

## Reproduce The Loop

```bash
cargo run -p veritas-cli -- --root examples/go-evolution-loop verify --lang go --target .
cargo run -p veritas-cli -- --root examples/go-evolution-loop score
cargo run -p veritas-cli -- --root examples/go-evolution-loop evolve --dry-run
```

The initial report should include these signals:

```text
Mutation score: 58% (generated 14, executed 12, killed 7, survived 4)
Fuzzing: generated harnesses 1, targets executed 3, failures 0, persisted repros 4
Differential replay: targets 3, cases 16
Evolution: suites 1, candidates 14, selected 12, average fitness 76%
Score: 55, Grade: Medium
```

Useful artifacts:

- `.veritas/mutations/go_campaign.json`: per-mutant campaign records.
- `.veritas/assertions/go_*.json`: assertion candidates for surviving mutants.
- `.veritas/corpus/go_*.json`: persisted repro metadata for parser inputs.
- `.veritas/differential/go_replay.json`: public API behavior replay cases.
- `.veritas/evolution/go_suite.json`: ranked candidate queue for the next generation.

The top candidate is a selected mutation candidate for `ParseInvoiceTotal`:

```text
Action: Add the smallest assertion that fails under this surviving mutant.
Keep if: the mutant moves from lived to killed in the next campaign.
Fitness: 95%
```

`veritas evolve --index 0 --evaluate` can materialize reviewable scaffolding, but the agent should replace placeholders with owned tests. For this fixture, the candidate becomes concrete assertions for invalid input, the inclusive upper bound, and rejected huge values:

```go
func TestParseInvoiceTotal(t *testing.T) {
	value, ok := ParseInvoiceTotal(" 10_000 ")
	if !ok || value != 10000 {
		t.Fatalf("expected normalized total, got %d ok=%v", value, ok)
	}
	value, ok = ParseInvoiceTotal("1000000")
	if !ok || value != 1000000 {
		t.Fatalf("expected boundary invoice total, got %d ok=%v", value, ok)
	}
	value, ok = ParseInvoiceTotal("not-a-number")
	if ok || value != 0 {
		t.Fatalf("expected invalid invoice total to be rejected with zero value, got %d ok=%v", value, ok)
	}
	value, ok = ParseInvoiceTotal("1000001")
	if ok || value != 0 {
		t.Fatalf("expected huge invoice total to be rejected with zero value, got %d ok=%v", value, ok)
	}
}
```

After adding the assertions and rerunning:

```bash
cargo run -p veritas-cli -- --root examples/go-evolution-loop verify --lang go --target .
cargo run -p veritas-cli -- --root examples/go-evolution-loop score
```

The follow-up report should show the improvement:

```text
Mutation score: 91% (generated 14, executed 12, killed 11, survived 0)
Fuzzing: generated harnesses 1, targets executed 3, failures 0
Differential replay: targets 3, cases 16
Evolution: suites 1, candidates 2, selected 0
Score: 98, Grade: High
```

That is the intended AI loop: Veritas finds weak behavior coverage, ranks the next assertion, the agent writes a real test, and the next report proves whether the candidate improved the system.
