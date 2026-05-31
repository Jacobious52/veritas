# go-mutation-score

`go-mutation-score` is a seeded benchmark for mutation scoring.

The normal tests and generated fuzz harnesses pass. A neutral arithmetic mutation should survive, while role and boundary mutations should be killed by the handwritten tests.
