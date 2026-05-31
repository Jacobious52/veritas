# Architecture

`veritas` is a Rust workspace with a CLI, core orchestration layer, language plugins, shared plugin API, and report renderers.

## Workspace

```text
crates/
  veritas-cli/          # clap CLI, command routing, output selection
  veritas-core/         # orchestration, planning, changed targets, artifacts, policy
  veritas-plugin-api/   # shared traits and report/data model
  veritas-rust/         # Rust detection, Tree-sitter symbols, proptest, cargo, coverage, mutation
  veritas-go/           # Go detection, Tree-sitter symbols, fuzzing, go test, coverage, mutation
  veritas-report/       # Markdown, SARIF, and JUnit renderers
fixtures/
  sample-rust/
  sample-go/
examples/
  rust-invoice/
  go-invoice/
docs/
```

## Core Flow

1. Detect projects through registered language plugins.
2. Discover verification targets.
3. Resolve changed targets from git diff hunks, staged changes, and untracked files.
4. Ask the planner for a bounded verification plan.
5. Generate reviewable artifacts.
6. Optionally write artifacts to the target project.
7. Run language tests, fuzzing, mutation checks, and coverage collection under budgets.
8. Add observation artifacts: baselines, replay manifests, feedback, repros, patches, and regression notes.
9. Assign stable finding IDs.
10. Render reports.

## Plugin Contract

Each language plugin implements:

- `detect_project(root) -> ProjectInfo`
- `discover_targets(root) -> Vec<VerificationTarget>`
- `generate_tests(target, plan) -> Vec<GeneratedArtifact>`
- `run_tests(root, artifacts, plan) -> TestRunResult`
- `collect_coverage(root) -> Option<CoverageReport>`
- `promote_regression(root, report, finding, index) -> Vec<GeneratedArtifact>`

Targets carry:

- language
- kind: project, package, file, or function
- path
- optional symbol
- optional signature
- optional line range
- risk

Artifacts carry:

- language
- kind
- target ID
- path
- contents
- planned/written/skipped status

Plugins can override regression promotion to emit language-owned executable scaffolds. The default plugin contract falls back to Markdown guidance, so future language plugins can adopt promotion incrementally.

## Planning

The deterministic planner is the default. It selects existing tests, generated tests, property tests, fuzzing, differential signature checks, mutation checks, and coverage feedback within the configured budget.

The optional external planner receives bounded JSON with:

- project
- target
- default plan
- constraints

Returned plans are clamped to the provided target, allowed strategy list, generated-test policy, and maximum budget. Planner failures fall back to deterministic planning unless `fail_on_error = true`.

## Execution Scheduler

Core exposes a small ordered parallel-job scheduler for language plugins. Plugins use it when jobs are independent and safe to run concurrently; Go fuzz targets use it today through `plugins.go.fuzz_concurrency`. Mutation probes remain serial because they temporarily rewrite source files in the target checkout.

## Tree-Sitter Use

Rust:

- discovers public free functions and public methods
- records symbol owners, line ranges, signatures, and call hints
- uses AST spans for mutation probes
- mutates comparison, boolean connector, arithmetic, boundary, default, and result-branch operators

Go:

- discovers exported functions and exported methods
- records receivers, line ranges, signatures, and call hints
- discovers fuzz targets from test files
- uses AST spans for mutation probes
- mutates comparison, nil/error, boolean connector, arithmetic, and return-default operators

Both plugins write symbol graph artifacts for AI and tooling consumption.

Observation artifacts include `.veritas/differential/*_replay.json` for behavior replay planning and `.veritas/regressions/*.md` for converting surviving mutants or minimized inputs into owned tests. `veritas promote-regression` asks the owning language plugin to turn a finding into a reviewable test scaffold.

## Reports

Report formats:

- Markdown
- JSON via `.veritas/report.json`
- SARIF 2.1.0
- JUnit XML

SARIF prefers target file and line range locations when a finding maps to a discovered target. JUnit trims long failure bodies for CI log hygiene.
