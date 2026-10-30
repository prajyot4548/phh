"""Unit tests for detector.py — run with:  python -m unittest discover tests"""
import unittest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import detect, verhoeff_ok, luhn_ok, risk_level


class TestVerhoeff(unittest.TestCase):
    def test_valid_checksum(self):
        self.assertTrue(verhoeff_ok("234567890124"))

    def test_invalid_checksum(self):
        self.assertFalse(verhoeff_ok("234567890123"))

    def test_wrong_length_rejected(self):
        self.assertFalse(verhoeff_ok("12345"))

    def test_non_digit_rejected(self):
        self.assertFalse(verhoeff_ok("23456789012A"))


class TestLuhn(unittest.TestCase):
    def test_valid_card_number(self):
        self.assertTrue(luhn_ok("4539578763621486"))   # test Visa number, passes Luhn

    def test_invalid_card_number(self):
        self.assertFalse(luhn_ok("4539578763621487"))

    def test_too_short_rejected(self):
        self.assertFalse(luhn_ok("1234"))


class TestDetect(unittest.TestCase):
    def test_pan_detected_and_masked(self):
        found = detect("My PAN is ABCPE1234F for tax filing.")
        self.assertIn("PAN", found)
        self.assertTrue(found["PAN"][0].endswith("234F"))
        self.assertNotIn("ABCPE1234F", found["PAN"][0])

    def test_clean_text_has_no_hits(self):
        self.assertEqual(detect("Just an ordinary paragraph about the weather today."), {})

    def test_aadhaar_requires_valid_checksum(self):
        # a random 12-digit number starting 2-9 should NOT be flagged unless checksum passes
        found = detect("Random number: 234567890123")
        self.assertNotIn("Aadhaar", found)

    def test_bank_account_needs_context(self):
        self.assertNotIn("Bank Account", detect("Order number: 123456789012"))
        self.assertIn("Bank Account", detect("Bank account number: 123456789012"))

    def test_email_detected(self):
        found = detect("Reach me at someone@example.com please.")
        self.assertIn("Email", found)

    def test_risk_level_high_for_aadhaar(self):
        found = detect("Aadhaar: 2345 6789 0124")
        self.assertEqual(risk_level(found), "high")

    def test_risk_level_low_for_nothing(self):
        self.assertEqual(risk_level({}), "low")


if __name__ == "__main__":
    unittest.main()
