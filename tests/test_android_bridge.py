import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app" / "src" / "main" / "python"))
import android_bridge


class AndroidBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "sample.bin"

    def tearDown(self):
        self.temp.cleanup()

    def test_inspect_bytes_hex_and_ascii(self):
        self.source.write_bytes(bytes(range(16)) + b"HELLO")
        result = json.loads(android_bridge.inspect_bytes(str(self.source), "0x10", "5"))
        self.assertEqual(result["bytes_read"], 5)
        self.assertIn("HELLO", result["hex_dump"])

    def test_inspect_bytes_rejects_oversized_request(self):
        self.source.write_bytes(b"A" * 5000)
        with self.assertRaises(ValueError):
            android_bridge.inspect_bytes(str(self.source), "0", "5000")

    def test_extract_ascii_strings_reports_offset(self):
        self.source.write_bytes(b"\x00START-STRING\x00short")
        result = json.loads(android_bridge.extract_ascii_strings(str(self.source), "4"))
        self.assertGreaterEqual(result["count"], 1)
        self.assertEqual(result["strings"][0]["offset"], 1)
        self.assertEqual(result["strings"][0]["text"], "START-STRING")

    def test_replace_utf8_creates_copy_and_preserves_source(self):
        self.source.write_bytes(b"before old after old")
        result = json.loads(android_bridge.replace_utf8_text(
            str(self.source), str(self.root / "out"), "old", "new"
        ))
        output = Path(result["output_path"])
        self.assertEqual(result["replacement_count"], 2)
        self.assertEqual(self.source.read_bytes(), b"before old after old")
        self.assertEqual(output.read_bytes(), b"before new after new")


if __name__ == "__main__":
    unittest.main()
