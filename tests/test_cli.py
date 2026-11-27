import io
import unittest

from pypromptcage.cli import _read_text_bounded


class CliTests(unittest.TestCase):
    def test_bounded_reader_accepts_small_input(self):
        self.assertEqual(_read_text_bounded(io.BytesIO(b"hello"), "test input"), "hello")

    def test_bounded_reader_rejects_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "bounded CLI input byte limit"):
            _read_text_bounded(io.BytesIO(b"x" * 500000), "test input")


if __name__ == "__main__":
    unittest.main()
