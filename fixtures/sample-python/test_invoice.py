import unittest

from invoice import authorize_refund, parse_invoice_total


class InvoiceTests(unittest.TestCase):
    def test_parse_invoice_total(self):
        self.assertEqual(parse_invoice_total("10_000"), (10000, True))
        self.assertEqual(parse_invoice_total("1000001"), (0, False))

    def test_authorize_refund(self):
        self.assertTrue(authorize_refund("support", 25000))
        self.assertFalse(authorize_refund("support", 25001))


if __name__ == "__main__":
    unittest.main()
