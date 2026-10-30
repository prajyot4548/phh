"""Unit tests for crypto_utils.py"""
import unittest
import sys, os, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import encrypt_file, decrypt_file, WrongPassword, password_strength, suggest_password


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "secret.txt")
        with open(self.path, "wb") as f:
            f.write(b"This file contains a PAN number: ABCPE1234F")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_round_trip(self):
        info = encrypt_file(self.path, "StrongPass1!")
        self.assertFalse(os.path.exists(self.path))
        self.assertTrue(os.path.exists(info["enc_path"]))
        out = decrypt_file(info["enc_path"], "StrongPass1!", info["sha256"])
        self.assertTrue(os.path.exists(out))
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"This file contains a PAN number: ABCPE1234F")

    def test_wrong_password_raises(self):
        info = encrypt_file(self.path, "StrongPass1!")
        with self.assertRaises(WrongPassword):
            decrypt_file(info["enc_path"], "WrongPassword!")

    def test_non_pii_guard_file_rejected(self):
        junk = os.path.join(self.dir, "junk.enc")
        with open(junk, "wb") as f:
            f.write(b"not a real encrypted file")
        with self.assertRaises(ValueError):
            decrypt_file(junk, "anything")


class TestPasswordStrength(unittest.TestCase):
    def test_empty_password(self):
        self.assertEqual(password_strength("")["score"], 0)

    def test_common_password_flagged_weak(self):
        self.assertEqual(password_strength("password")["score"], 0)

    def test_strong_password_scores_high(self):
        self.assertGreaterEqual(password_strength("Mint#River88")["score"], 4)

    def test_suggest_password_passes_own_check(self):
        suggestion = suggest_password()
        self.assertGreaterEqual(password_strength(suggestion)["score"], 3)


if __name__ == "__main__":
    unittest.main()
