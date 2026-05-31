# Go Productionization Handoff

This document is the durable handoff for making `veritas` useful on a large AI-written Go codebase. The intended production use case is a repo with hundreds of thousands of lines, existing unit/integration tests, and some existing fuzzing.

## Goal

For a PR or branch, `veritas` should answer a different question than regular testing:

> Would the existing and generated tests catch the kinds of mistakes AI-written Go code tends to make in the changed/risky code?

That means it should be changed-scope, low-noise, time-budgeted, and adversarial. It should not just run `go test ./...` and add generic fuzz scaffolds.

## Current State

Implemented foundations:

- Go project detection through `go.mod`.
- Public Go function discovery with tree-sitter.
- Changed-file targeting through core git diff mapping.
- Generated Go fuzz harnesses for supported functions.
- Existing Go test execution.
- Relevant generated fuzz execution.
- Deterministic source-level mutation checks.
- Coverage collection through `go test -coverprofile`.
- Cleanup of `.veritas`, Rust generated tests, and Go `veritas_fuzz_test.go`.

The current productionization pass adds:

- `go list -json ./...` package graph discovery for package-scoped execution.
- Package/reverse-dependency scoped `go test` when artifacts identify changed packages.
- Existing fuzz target discovery from `*_test.go` files.
- Relevant existing fuzz execution for packages touched by generated artifacts/mutation checks.
- Broader generated fuzz support for common Go fuzz argument types.
- Stronger semantic mutation operators for boolean guards, nil/error checks, comparisons, and default values.
- Configurable transitive reverse-dependency depth, package caps, fuzz target caps, existing-fuzz toggles, build tags, command timeouts, and mutation caps.
- A `GoVerificationContext` that discovers package graph, exported functions, and handwritten/generated fuzz targets once for each Go verification execution path.
- Package-awareness report artifacts under `.veritas/feedback/go_packages.md` with changed package tests, handwritten fuzz, generated fuzz, and reverse-dependency context.
- Machine-readable Go package graph artifacts under `.veritas/package_graph/go.json`.
- Multi-module discovery for repositories with multiple `go.mod` roots, with scoped commands run from the owning module.
- Severity-bearing findings plus CI policy filters by severity, language, artifact kind, and target risk.
- AST-scoped Go mutation candidate selection instead of raw function-body substring replacement.
- Fuzz failure repro path capture for package-local `testdata/fuzz/<Name>/...` corpus promotion suggestions.

## Production Requirements

### 1. Changed-Scope Targeting

Required behavior:

- Map changed Go files to packages.
- Include direct reverse dependencies for changed packages.
- Prefer package-scoped commands over repo-wide commands.
- Fall back to `./...` only when no narrower target exists.

Implemented baseline:

- Package graph discovery via `go list -json ./...`.
- Package args are derived from generated artifact paths and target IDs.
- Direct reverse dependencies are included when graph data is available.

Next work:

- Add multi-module traversal for monorepos where changed packages live below several `go.mod` roots.
- Persist machine-readable package graph data in JSON in addition to the Markdown feedback artifact.

### 2. Existing Test And Fuzz Awareness

Required behavior:

- Detect existing tests and fuzz targets.
- Run relevant existing fuzz targets for changed packages.
- Report changed packages with tests but no fuzzing, and fuzzing but no assertions around changed behavior.

Implemented baseline:

- Existing fuzz targets are discovered from `*_test.go`.
- Relevant existing fuzz targets run with the configured Go fuzz budget.

Next work:

- Promote captured `testdata/fuzz/<Name>/...` corpus files into explicit regression-test patches when the function shape supports stable assertions.
- Detect fuzz targets that execute changed packages but do not assert changed behavior.
- Add corpus minimization orchestration beyond the Go toolchain's default failing-input persistence.

### 3. Type-Aware Harness Generation

Required behavior:

- Generate useful harnesses for common function shapes, not only `string` and `[]byte`.
- Eventually support structs, JSON/protobuf payloads, HTTP handlers, repositories, and permission contexts.

Implemented baseline:

- Functions with one or more supported primitive Go fuzz parameters can be fuzzed.
- Supported types include string, bytes, bool, signed/unsigned integers, and floats.

Next work:

- Use `go/types` or `go/packages`-style metadata instead of text-only parameter parsing.
- Generate struct values from package types and constructors.
- Add round-trip templates for `Marshal`/`Unmarshal`, `Parse`/`Format`, and `Validate`/`Normalize`.
- Add HTTP handler harnesses around `httptest`.
- Add interface fake generation for repository/service boundaries.

### 4. Semantic Mutation Checks

Required behavior:

- Mutate the kinds of behavior AI often gets wrong.
- Classify survivors by risk and produce actionable test suggestions.

Implemented baseline:

- Mutation operators cover error/nil branch inversions, boolean return flips, comparison boundary changes, equality/inequality flips, numeric defaults, string defaults, and error suppression.

Next work:

- Add operators for auth, permissions, money, parsing, serialization, and error handling.
- Move from syntactic AST mutations to typed AST mutations so operators understand identifiers, constants, and package-level semantics.
- Expand domain operators for auth, permissions, money, parsing, serialization, and error handling beyond contextual labels.
- Emit candidate test patches for surviving mutants instead of assertion guidance only.

### 5. Regression Artifact Workflow

Required behavior:

- Generated artifacts should be reviewable, stable, and promotable.
- Failing fuzz/proptest inputs should become regression tests or corpus entries.

Implemented baseline:

- `.veritas/repros` and cleanup exist.

Next work:

- Add `veritas promote-repro` or similar.
- Materialize captured `testdata/fuzz/<Name>/...` repros into reviewable regression patches.
- Add stable artifact ownership metadata.
- Add report links from survivors to candidate test patches.

### 6. CI Policy Controls

Required behavior:

- Differentiate warning vs failure by severity, risk, artifact kind, target type, and language.

Next work:

- Add `--changed` CI profile defaults.
- Add baseline/quarantine support for known flaky fuzz findings.

### 7. Scale Controls

Required behavior:

- Avoid full repo work unless explicitly requested.
- Respect time budgets and package count limits.

Implemented baseline:

- Package-scoped testing is available when artifacts identify target packages.
- Go command timeout, package cap, fuzz target cap, and mutation cap controls are configurable.

Next work:

- Add parallel package execution.
- Cache `go list` results during a run.
- Add monorepo/multi-module traversal.

## Suggested Next Agent Tasks

1. Harden multi-module traversal against nested vendored modules and workspace files.
2. Promote Go fuzz corpus repros into candidate regression patches.
4. Move mutation operators from syntactic AST targeting to typed semantic targeting.
5. Add changed-scope CI profile defaults and quarantine/baseline controls for known flaky fuzz findings.
6. Add parallel package execution with global run budget accounting.
7. Generate assertion patches from coverage gaps and surviving mutants.

## Validation Commands

Use these after each productionization slice:

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p veritas-cli -- verify --root fixtures/sample-go --lang go --target .
cargo run -p veritas-cli -- cleanup --root fixtures/sample-go --dry-run
```

For a large production repo, start non-blocking:

```bash
veritas verify --changed --lang go
veritas report --format sarif
```

Do not make `veritas` a blocking CI gate until package scoping, timeout controls, severity policy, and known-finding baselines are in place.
