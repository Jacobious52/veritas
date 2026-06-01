# AI Agent Guide

Use this document when an AI coding agent is editing a repository that should be checked with `veritas`.

## Copy-Paste Instructions

```text
Use veritas as the adversarial verification loop for this change.

Install if needed:
  cargo install veritas-cli --locked

If the crate release is not available yet:
  cargo install --git https://github.com/Jacobious52/veritas veritas-cli --locked

Before editing broadly:
  veritas review-ai
  Read .veritas/ai/change_digest.md and .veritas/ai/agent_feedback.md.

After making code or test changes:
  veritas verify --changed --profile ci
  veritas score

If veritas reports findings:
  1. Use veritas explain <finding-id>.
  2. Inspect .veritas/assertions/ and .veritas/corpus/ for structured assertion and replay seeds.
  3. Run veritas replay-corpus --dry-run to see which persisted seeds are executable.
  4. Prefer adding focused regression tests or fuzz corpus entries before changing production code.
  5. Run veritas promote-regression --index <finding-index> when a finding should become an owned test scaffold.
  6. Inspect .veritas/patches/, .veritas/repros/, .veritas/regressions/, .veritas/differential/, .veritas/budgets/, .veritas/promotions/, and .veritas/symbol_graph/.
  7. Rerun veritas verify --changed --profile ci.

Do not ignore warning/error findings without explaining why. Only accept a finding baseline with:
  veritas accept-baseline --id <finding-id>

Refresh the quality baseline only after a reviewed good state:
  veritas accept-quality-baseline

Clean generated artifacts before finalizing unless intentionally committing reviewed artifacts:
  veritas cleanup
```

## Review Loop

1. Run `veritas review-ai`.
2. Read `.veritas/ai/change_digest.md` for changed files, changed target symbols, risk, and diff context.
3. Read `.veritas/ai/agent_feedback.md` for concrete agent instructions.
4. Edit code or tests.
5. Run `veritas verify --changed --profile ci`.
6. Run `veritas score` to summarize confidence, remaining risks, and next steps.
7. Run `veritas replay-corpus --dry-run` to separate executable corpus seeds from guidance-only mutation repros.
8. For each finding, run `veritas explain <finding-id>`.
9. Promote useful repros with `veritas promote-repro --dry-run` and then `veritas promote-repro` when the promotion note is useful.
10. Promote test gaps with `veritas promote-regression --dry-run` and then `veritas promote-regression --index <n>` when a finding should become a package-owned test scaffold.
11. Inspect evolutionary candidates with `veritas evolve --dry-run`, then apply one selected candidate with `veritas evolve --index <n> --evaluate` or all safe selected candidates with `veritas evolve --all-selected --evaluate`.
12. Run `veritas cleanup` before final response unless generated artifacts are intentionally reviewed and committed.

## Concrete Evolution Loop

Use `examples/go-evolution-loop` as the local reference when teaching an agent how the loop should feel:

```bash
cargo run -p veritas-cli -- --root examples/go-evolution-loop verify --lang go --target .
cargo run -p veritas-cli -- --root examples/go-evolution-loop score
cargo run -p veritas-cli -- --root examples/go-evolution-loop evolve --dry-run
```

The first report produces `14` candidates, `12` selected candidates, `4` surviving mutants, a `58%` mutation score, and a `55` confidence score. The top selected candidate asks for the smallest assertion that kills a surviving `ParseInvoiceTotal` mutant. After the agent turns that candidate into real parser assertions for invalid input, the inclusive `1000000` boundary, and rejected huge values, the follow-up report reaches a `91%` mutation score, `0` surviving mutants, and a `98` confidence score.

See `docs/evolution.md` for the exact before/candidate/after commands, expected metrics, and artifact paths.

See `docs/ai-verification-loops.md` for concrete Rust, Go, Python, and agent-repair examples that can be pasted into onboarding docs or issue comments.

## AI-Facing Artifacts

`veritas` writes artifacts designed to be pasted back into an AI agent:

- `.veritas/ai/change_digest.md`: changed files, changed targets, and diff excerpts
- `.veritas/ai/agent_feedback.md`: next-step instructions for the coding agent
- `.veritas/symbol_graph/*.json`: discovered symbols, line ranges, owners/receivers, risks, and call hints
- `.veritas/package_graph/go.json`: Go modules, packages, imports, fuzz targets, tests, and run reasons
- `.veritas/feedback/*.md`: coverage and mutation feedback
- `.veritas/assertions/*.json`: structured assertion candidates with source finding, domain, seed inputs, expected behavior, and replay command
- `.veritas/corpus/*.json`: persistent repro seed metadata for later replay
- `.veritas/corpus/replay_result.json`: corpus replay summary from `veritas replay-corpus`
- `.veritas/differential/*.json`: behavior replay manifests and result summaries for selected public APIs
- `.veritas/budgets/*.json`: command budget and resource-limit metadata
- `.veritas/trends/*.json`: mutation score attribution and quality baseline deltas
- `.veritas/mutations/*_campaign.json`: per-mutant status records for killed, lived, runnable, timed-out, not-viable, and skipped mutants
- `.veritas/evolution/*_candidates.json`: typed candidate queue with fitness signals for the next generation loop
- `.veritas/evolution/*_suite.json`: selected evolutionary testing suite. Candidates are ranked by expected mutation, replay, finding, confidence, and review-cost impact so an agent can promote the highest-value assertions, corpus seeds, replay checks, or budget refinements first.
- `.veritas/evolution/*_generation_*.json`: persisted evolution attempts with applied candidates, status transitions, quality deltas, and outcome.
- `.veritas/repros/*.md`: command and input summaries for reproducible failures
- `.veritas/patches/*.md`: candidate verification patch guidance
- `.veritas/regressions/*.md`: generated assertion guidance for surviving mutants and minimized inputs
- `.veritas/promotions/*.md`: repro promotion notes created by `veritas promote-repro`
- Rust `tests/veritas_regression_*.rs` and Go `veritas_regression_*_test.go`: ignored/skipped executable scaffolds created by `veritas promote-regression`

Generated tests are reviewable artifacts, not automatically trusted source.

## Agent Rules

- Keep verification changed-scope unless the user explicitly asks for a full workspace run.
- Treat warning-level surviving mutants as evidence of missing assertions, not as proof of production defects.
- Prefer a small regression test before editing production code when a generated or fuzz repro exposes behavior.
- Turn `.veritas/assertions/*.json`, `.veritas/regressions/*.md`, and `.veritas/differential/*.json` into handwritten assertions when behavior compatibility matters.
- Treat `.veritas/evolution/*_suite.json` as the next-generation work queue. Use `veritas evolve --dry-run` first, apply selected candidates one at a time with `--evaluate`, inspect `.veritas/evolution/*_generation_*.json`, rerun `veritas verify` when needed, and keep only candidates that improve mutation, replay, finding, or confidence metrics.
- Do not widen fuzz time, reverse dependency depth, package caps, or coverage scope without explaining the runtime tradeoff.
- On shared hosts, keep Rust coverage disabled and use systemd scope limits when running broad Rust verification.
