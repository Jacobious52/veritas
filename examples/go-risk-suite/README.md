# Go Risk Suite

Seeded Go benchmark covering auth/permission, money thresholds, parsing, serialization, and boundary-style mutation operators.

Expected signal:

- handwritten tests should kill several boundary and boolean mutants
- remaining survivors should produce assertion candidates and corpus metadata
- generated fuzz harnesses should exercise primitive input surfaces
