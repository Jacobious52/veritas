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
  rust-commerce/
  go-api-service/
  rust-mutation-score/
  go-mutation-score/
  rust-risk-suite/
  go-risk-suite/
  rust-evolution-loop/
  go-evolution-loop/
  veritas-bench.toml
docs/
  index.html            # GitHub Pages landing page
  evolution.md          # concrete before/candidate/after evolution demo
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
9. Add structured assertion candidates, corpus entries, replay result summaries, and budget metadata.
10. Assign stable finding IDs.
11. Render reports and confidence scores.

## Plugin Contract

Each language plugin implements:

- `capabilities() -> Vec<PluginCapability>`
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

Plugins advertise capabilities such as symbol graphs, property tests, fuzzing, mutation checks, differential replay, corpus replay, regression promotion, and resource budgets. Plugins can override regression promotion to emit language-owned executable scaffolds. The default plugin contract falls back to Markdown guidance, so future language plugins can adopt promotion incrementally.

## Planning

The deterministic planner is the default. It selects existing tests, generated tests, property tests, fuzzing, differential signature checks, mutation checks, and coverage feedback within the configured budget.

The optional external planner receives bounded JSON with:

- project
- target
- default plan
- constraints

Returned plans are clamped to the provided target, allowed strategy list, generated-test policy, and maximum budget. Planner failures fall back to deterministic planning unless `fail_on_error = true`.

## Execution Scheduler

Core exposes a small ordered parallel-job scheduler for language plugins. Plugins use it when jobs are independent and safe to run concurrently; Go fuzz targets use it through `plugins.go.fuzz_concurrency`.

Core also exposes a plugin-generic isolated mutation root helper. A language plugin can copy the target project into a temporary root, apply one mutant there, run the owning test command, and let cleanup happen on drop. Go and Rust mutation use this path when `[mutation].workers > 1`; `workers = 1` keeps the serial source-rewrite path for smaller local runs. Mutation metrics record requested workers, effective workers, timed-out mutants, skipped mutants, and isolation failures so CI can separate performance behavior from mutation quality.

## Benchmark Suites

`veritas bench` reads a `veritas-bench.toml` manifest, copies each case into a temporary directory, runs normal verification, and scores expected finding substrings, artifact kinds, command substrings, and thresholds. Its JSON output includes command counts, finding counts by severity, artifact counts by kind, mutation score, mutant generated/executed/killed/survived/skipped counts, mutation worker metrics, generated-test failure counts, assertion candidate counts, corpus entries, replay cases, budget skips/timeouts, fuzz execution/failure counts, persisted repro counts, evolution candidates, and selected evolution candidates. This keeps seeded benchmark projects clean while giving generation, fuzzing, mutation, and reporting changes a concrete regression scoreboard.

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
- mutates comparison, nil/error, boolean connector, arithmetic, bitwise, assignment, increment/decrement, unary negation, loop-control, literal, self-assignment, and return-default operators

Python:

- discovers production functions and methods with Tree-sitter
- records class owners, line ranges, signatures, and call hints
- runs `python3 -m unittest discover`
- executes differential replay for single-argument free functions

All language plugins write symbol graph artifacts for AI and tooling consumption. Rust and Go include mutation and richer generated-test paths today; Python is the third-language SDK spike that proves the core contract is not Rust/Go-specific.

Observation artifacts include `.veritas/assertions/*.json` for structured assertion candidates, `.veritas/corpus/*.json` and `.veritas/corpus/replay_result.json` for persistent repro seed metadata and replay results, `.veritas/differential/*_replay.json` and `*_result.json` for behavior replay planning/results, `.veritas/budgets/*.json` for command budget metadata, `.veritas/trends/*.json` for mutation attribution and quality baseline deltas, `.veritas/mutations/*_campaign.json` for per-mutant campaign records, `.veritas/regressions/*.md` for converting surviving mutants or minimized inputs into owned tests, and `.veritas/evolution/*.md`, `*_candidates.json`, and `*_suite.json` for the next AI candidate-generation loop. Evolution suites are plugin-neutral ranked work queues: Rust, Go, and future Tree-sitter plugins feed the same candidate model with mutation survivors, uncovered mutants, assertion candidates, corpus seeds, replay opportunities, and budget risks. `veritas promote-regression` asks the owning language plugin to turn a finding into a reviewable test scaffold.

## Reports

Report formats:

- Markdown
- JSON via `.veritas/report.json`
- SARIF 2.1.0
- JUnit XML

SARIF prefers target file and line range locations when a finding maps to a discovered target. JUnit trims long failure bodies for CI log hygiene.

`veritas score` reads `.veritas/report.json` and produces a compact confidence score from mutation score, findings, assertion candidates, replay cases, corpus entries/replay, and budget health. If `.veritas/baselines/quality.json` exists, the score includes mutation/confidence/survivor deltas. `veritas accept-quality-baseline` refreshes that baseline after a reviewed good state.
