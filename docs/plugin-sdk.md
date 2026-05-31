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

- `replay_behavior` executes seeded differential replay cases and returns structured observations.
- `promote_regression` turns findings or evolution candidates into owned language tests.

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

## Third-Language Spike

`veritas-python` is the SDK spike. It currently supports:

- Python project detection from `pyproject.toml`, `setup.py`, or `.py` files
- Tree-sitter function and method discovery
- symbol graph artifacts
- `python3 -m unittest discover`
- executable differential replay for single-argument free functions

This gives future plugins a concrete path without requiring Rust/Go-specific assumptions in core.
