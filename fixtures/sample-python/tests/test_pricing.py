import unittest

from sample_python import normalize_discount_code


class PricingTests(unittest.TestCase):
    def test_normalize_discount_code(self):
        self.assertEqual(normalize_discount_code(" spring-10 "), "SPRING10")


if __name__ == "__main__":
    unittest.main()
