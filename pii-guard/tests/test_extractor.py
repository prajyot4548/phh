"""Unit tests for extractor.py — covers the formats that need no optional libraries."""
import unittest
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from extractor import extract_text, SUPPORTED


class TestExtractText(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _write(self, name, content):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def test_plain_text_file(self):
        path = self._write("a.txt", "PAN ABCPE1234F")
        self.assertIn("ABCPE1234F", extract_text(path))

    def test_csv_file(self):
        path = self._write("a.csv", "name,pan\nAnil,ABCPE1234F")
        self.assertIn("ABCPE1234F", extract_text(path))

    def test_unsupported_extension_returns_empty(self):
        path = self._write("a.exe", "binary-ish content")
        self.assertEqual(extract_text(path), "")

    def test_supported_set_includes_core_formats(self):
        for ext in (".pdf", ".docx", ".txt", ".jpg", ".png"):
            self.assertIn(ext, SUPPORTED)


if __name__ == "__main__":
    unittest.main()
