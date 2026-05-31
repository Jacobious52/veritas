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

If veritas reports findings:
  1. Use veritas explain <finding-id>.
  2. Prefer adding focused regression tests or fuzz corpus entries before changing production code.
  3. Inspect .veritas/patches/, .veritas/repros/, .veritas/promotions/, and .veritas/symbol_graph/.
  4. Rerun veritas verify --changed --profile ci.

Do not ignore warning/error findings without explaining why. Only accept a finding baseline with:
  veritas accept-baseline --id <finding-id>

Clean generated artifacts before finalizing unless intentionally committing reviewed artifacts:
  veritas cleanup
```

## Review Loop

1. Run `veritas review-ai`.
2. Read `.veritas/ai/change_digest.md` for changed files, changed target symbols, risk, and diff context.
3. Read `.veritas/ai/agent_feedback.md` for concrete agent instructions.
4. Edit code or tests.
5. Run `veritas verify --changed --profile ci`.
6. For each finding, run `veritas explain <finding-id>`.
7. Promote useful repros with `veritas promote-repro --dry-run` and then `veritas promote-repro` when the promotion note is useful.
8. Run `veritas cleanup` before final response unless generated artifacts are intentionally reviewed and committed.

## AI-Facing Artifacts

`veritas` writes artifacts designed to be pasted back into an AI agent:

- `.veritas/ai/change_digest.md`: changed files, changed targets, and diff excerpts
- `.veritas/ai/agent_feedback.md`: next-step instructions for the coding agent
- `.veritas/symbol_graph/*.json`: discovered symbols, line ranges, owners/receivers, risks, and call hints
- `.veritas/package_graph/go.json`: Go modules, packages, imports, fuzz targets, tests, and run reasons
- `.veritas/feedback/*.md`: coverage and mutation feedback
- `.veritas/repros/*.md`: command and input summaries for reproducible failures
- `.veritas/patches/*.md`: candidate verification patch guidance
- `.veritas/promotions/*.md`: repro promotion notes created by `veritas promote-repro`

Generated tests are reviewable artifacts, not automatically trusted source.

## Agent Rules

- Keep verification changed-scope unless the user explicitly asks for a full workspace run.
- Treat warning-level surviving mutants as evidence of missing assertions, not as proof of production defects.
- Prefer a small regression test before editing production code when a generated or fuzz repro exposes behavior.
- Do not widen fuzz time, reverse dependency depth, package caps, or coverage scope without explaining the runtime tradeoff.
- On shared hosts, keep Rust coverage disabled and use systemd scope limits when running broad Rust verification.
