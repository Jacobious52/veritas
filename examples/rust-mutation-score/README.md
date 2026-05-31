# rust-mutation-score

`rust-mutation-score` is a seeded benchmark for mutation scoring.

The normal tests pass. One neutral arithmetic mutant should survive, while other branch and boundary mutants should be killed by the handwritten assertions. This gives `veritas bench` a stable mutation-score case instead of only generated-test-failure cases.
