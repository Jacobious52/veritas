# Veritas Plugin SDK

Veritas language plugins are intentionally small, CLI-first adapters. A plugin owns language-specific discovery and execution, while `veritas-core` owns planning, report quality, artifacts, and AI feedback loops.

## Required Contract

Every plugin implements `LanguagePlugin` from `veritas-plugin-api`:

- `id` and `display_name` define the stable language key.
- `detect_project` answers whether the current root belongs to the language.
- `discover_targets` returns project, package/file, and function targets with stable IDs, paths, signatures, line ranges, and risk.
- `generate_tests` writes reviewable artifacts such as symbol graphs, fuzz harnesses, property tests, or mutation manifests.
- `run_tests` executes the project’s native test command under plugin time budgets.
- `collect_coverage` returns best-effort coverage feedback or an explicit skipped report.

Optional hooks make plugins more powerful without forcing every language to implement everything at once:

- `replay_behaviors` executes seeded differential replay cases in a target-level batch and returns structured observations keyed by case name. `replay_behavior` remains as the compatibility fallback.
- `promote_regression` turns findings or evolution candidates into owned language tests.

## Contract Checklist

A production plugin should make these fields stable before it is advertised as a first-class language:

- target IDs use `<language>:<relative/path>:<symbol>` for functions and stable package/file IDs for broader targets
- paths are source-relative and never absolute inside generated artifacts
- function targets include line ranges whenever Tree-sitter can provide them
- generated artifacts declare an owning `target_id`, `ArtifactKind`, status, reviewable contents, and cleanup-safe paths
- native commands honor plugin time budgets and produce `CommandRecord` entries with duration and status
- coverage reports either include files/uncovered ranges or an explicit disabled/unavailable summary
- mutation campaigns report generated, runnable, executed, killed, survived, skipped, and domain/operator attribution
- replay hooks batch target-level cases when possible and fall back cleanly when a signature is unsupported
- evolution candidates include proposed action, keep criteria, proof commands, and done-when criteria
- cleanup leaves handwritten tests alone and removes only Veritas-owned generated artifacts

The CLI integration suite verifies this contract across the Rust, Go, and Python fixtures by checking target IDs, symbol metadata, generated artifact shape, phase timings, and report quality fields.

## Stable Target IDs

Use this shape for function targets:

```text
<language>:<relative/path>:<symbol>
```

Examples:

```text
rust:src/lib.rs:parse_invoice_total
go:invoice.go:ParseInvoiceTotal
python:invoice.py:parse_invoice_total
```

Stable IDs are important because baselines, mutation trends, replay observations, and AI promotion loops all join on the same target identity.

## Tree-Sitter Expectations

New language plugins should use Tree-sitter for symbol discovery when a grammar exists. At minimum, discover:

- public or externally callable functions/methods
- source-relative path
- symbol name, including owner where useful
- signature or signature-like header text
- line range
- direct call names when available

## Third-Language Plugin Path

`veritas-python` is the third language plugin and the reference path for future SDK adopters. It currently supports:

- Python project detection from `pyproject.toml`, `setup.py`, or `.py` files
- Tree-sitter function and method discovery
- symbol graph artifacts
- pytest detection with fallback to `python3 -m unittest discover`
- coverage.py summaries when coverage is enabled and coverage.py is installed
- executable mutation checks for simple Python AST-adjacent operators
- batched executable differential replay for supported primitive free-function arguments

This gives future plugins a concrete path without requiring Rust/Go-specific assumptions in core.

## Skeleton Plugin

`examples/plugin-skeleton` contains a minimal Rust crate that implements the `LanguagePlugin` trait with stable project/function targets, a symbol graph artifact, native command result wiring, and coverage fallback. It is intentionally small so a new language plugin can copy it, add a Tree-sitter grammar, and then grow into mutation, replay, coverage, and regression promotion one hook at a time.
