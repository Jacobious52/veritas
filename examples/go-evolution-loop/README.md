# Go Evolution Loop

Medium-sized Go fixture for the evolutionary verification loop.

The code mixes realistic AI-risk surfaces:

- refund authorization with a delegated support threshold
- invoice total parsing with normalization and an upper bound
- settlement serialization for retry/reject/settled states

The handwritten tests intentionally cover useful behavior while leaving some mutation and replay gaps. A Veritas run should produce:

- mutation survivors that become assertion candidates
- generated fuzz targets and corpus metadata
- replay cases for public APIs
- `.veritas/evolution/go_suite.json` with multiple selected candidates

Useful loop:

```bash
veritas verify --lang go --target .
veritas evolve --dry-run
veritas evolve --index 0 --evaluate
```
