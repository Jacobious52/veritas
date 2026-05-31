# go-api-service

`go-api-service` is a seeded benchmark example for `veritas`.

It models a small API boundary with token normalization, JSON-ish payload parsing, permission checks, and status handling. The handwritten tests cover the happy path, while generated fuzzing should catch malformed request inputs that an AI coding agent might forget to harden.
