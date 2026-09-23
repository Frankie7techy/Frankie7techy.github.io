"""Lightweight static entropy analyzer for binary files.

Computes Shannon entropy per sliding window and produces a summary.
Designed for defensive analysis of packed/encrypted sections.

Usage:
    from bin_scanner.entropy import entropy_score, scan_file_entropy
"""

import math
import os
from collections import Counter
from typing import Tuple, List, Dict


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def entropy_score(data: bytes, window_size: int = 256) -> Tuple[float, List[float]]:
    """Return average entropy and per-window list."""
    if window_size < 1:
        raise ValueError("window_size must be >= 1")
    if len(data) < window_size:
        return shannon_entropy(data), [shannon_entropy(data)]
    scores = []
    for i in range(0, len(data) - window_size + 1, window_size):
        window = data[i:i+window_size]
        scores.append(shannon_entropy(window))
    avg = sum(scores) / len(scores) if scores else 0.0
    return avg, scores


def scan_file_entropy(file_path: str, window_size: int = 4096, threshold: float = 7.8) -> Dict:
    """Scan file and return high-entropy regions."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(file_path)
    file_size = os.path.getsize(file_path)
    high_regions = []
    # Read in chunks to avoid loading huge files entirely
    avg_entropy = 0.0
    total_windows = 0
    # For simplicity, read whole file for moderate sizes; fall back to chunked scan
    # Defensive: limit to 100 MB for full read
    if file_size > 100 * 1024 * 1024:
        # Streamed scan
        with open(file_path, 'rb') as f:
            buffer = b''
            offset = 0
            while True:
                chunk = f.read(window_size * 4)
                if not chunk:
                    break
                buffer += chunk
                while len(buffer) >= window_size:
                    window = buffer[:window_size]
                    e = shannon_entropy(window)
                    avg_entropy += e
                    total_windows += 1
                    if e >= threshold:
                        high_regions.append({'offset': offset, 'entropy': e})
                    offset += window_size
                    buffer = buffer[window_size:]
        avg_entropy = avg_entropy / total_windows if total_windows else 0.0
    else:
        with open(file_path, 'rb') as f:
            data = f.read()
        avg, scores = entropy_score(data, window_size)
        avg_entropy = avg
        # Identify high entropy windows
        for i, e in enumerate(scores):
            if e >= threshold:
                high_regions.append({'offset': i * window_size, 'entropy': e})
    return {
        'file_path': file_path,
        'file_size': file_size,
        'average_entropy': avg_entropy,
        'window_size': window_size,
        'threshold': threshold,
        'high_entropy_regions': high_regions,
        'high_region_count': len(high_regions)
    }
