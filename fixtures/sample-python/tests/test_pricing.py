import unittest

from sample_python import normalize_discount_code, normalized_discount_tags


class PricingTests(unittest.TestCase):
    def test_normalize_discount_code(self):
        self.assertEqual(normalize_discount_code(" spring-10 "), "SPRING10")

    def test_normalized_discount_tags_is_over_specific_about_order(self):
        self.assertEqual(normalized_discount_tags("vip, beta"), ["beta", "vip"])


if __name__ == "__main__":
    unittest.main()
