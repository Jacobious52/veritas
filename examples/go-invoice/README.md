# Go Invoice Test Bed

This is a deliberately small Go project for dogfooding `veritas`.

The handwritten tests pass, but `ParseInvoiceTotal` assumes every input contains an `=` and should be caught by generated fuzz harnesses.

Run:

```bash
go test ./...
cargo run -p veritas-cli -- verify --root examples/go-invoice --lang go --target .
```
