# Rust Risk Suite

Seeded Rust benchmark covering auth/permission, money thresholds, parsing, serialization, and boundary-style mutation operators.

Expected signal:

- some comparison/boolean mutants should be killed by handwritten assertions
- at least one survivor should remain for Veritas to convert into assertion candidates
- generated property quality metrics should count no-panic and deterministic properties
