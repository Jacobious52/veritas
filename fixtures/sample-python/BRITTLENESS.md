# Brittleness Probe Fixture

`normalized_invoice_tags` and `normalized_discount_tags` have a behavior contract of returning normalized tags, not a contractual ordering guarantee. The current tests intentionally assert exact ordering:

```python
self.assertEqual(normalized_invoice_tags("urgent, paid"), ["paid", "urgent"])
```

The Python plugin can replace `sorted(...)` with `list(...)` as a behavior-preserving brittleness probe. If that probe is killed, the preferred rewrite is to assert the behavior without coupling to implementation ordering:

```python
self.assertCountEqual(normalized_invoice_tags("urgent, paid"), ["paid", "urgent"])
```

Keep exact-order assertions only when ordering is part of the public API.
