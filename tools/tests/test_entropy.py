import unittest
import tempfile
import os
from bin_scanner.entropy import shannon_entropy, entropy_score, scan_file_entropy


class TestEntropy(unittest.TestCase):
    def test_shannon_entropy_uniform(self):
        data = bytes([0] * 256)
        # Actually uniform distribution across 256 values = 8 bits
        data = bytes(range(256)) * 2
        e = shannon_entropy(data)
        self.assertAlmostEqual(e, 8.0, places=1)

    def test_shannon_entropy_zero(self):
        data = b'\x00' * 1024
        e = shannon_entropy(data)
        self.assertAlmostEqual(e, 0.0, places=6)

    def test_entropy_score_small(self):
        data = b'AAAAAA'
        avg, scores = entropy_score(data, window_size=3)
        self.assertGreaterEqual(avg, 0)

    def test_entropy_score_rejects_zero_window(self):
        # cli.py passes --window straight through; 0 used to die with
        # an opaque 'range() arg 3 must not be zero' ValueError.
        with self.assertRaises(ValueError):
            entropy_score(b'A' * 64, window_size=0)

    def test_scan_file_entropy(self):
        # Create temporary file with low entropy
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b'\x00' * 1024)
            name = tf.name
        try:
            res = scan_file_entropy(name, window_size=256, threshold=7.8)
            self.assertEqual(res['file_size'], 1024)
            self.assertLess(res['average_entropy'], 0.1)
            self.assertEqual(res['high_region_count'], 0)
        finally:
            os.unlink(name)


if __name__ == '__main__':
    unittest.main()
