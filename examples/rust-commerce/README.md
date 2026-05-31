# rust-commerce

`rust-commerce` is a seeded benchmark example for `veritas`.

The handwritten tests cover ordinary commerce flows, but the public API still contains realistic AI-style mistakes around parsing, refund boundaries, and permission defaults. `veritas bench` copies this project to a temporary directory and expects generated verification to expose at least one hidden assumption.
