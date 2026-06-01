# Veritas Plugin Skeleton

This is a copyable starting point for a future Tree-sitter language plugin.

The important contract is not the exact code shape; it is the data the plugin
returns to `veritas-core`:

- stable target IDs
- source-relative paths
- line ranges from Tree-sitter
- generated artifact ownership
- native command budgets
- optional coverage, mutation, replay, and regression promotion hooks

To adapt this skeleton:

1. Replace `example` with your language key.
2. Add the Tree-sitter grammar crate for your language.
3. Implement `discover_targets` with project/file/function targets.
4. Emit a symbol graph artifact first, then add properties, fuzzing, mutation,
   replay, and coverage incrementally.
5. Add a fixture and golden scan/report assertions before advertising the
   plugin as production-ready.

See [../../docs/plugin-sdk.md](../../docs/plugin-sdk.md) for the full contract.
