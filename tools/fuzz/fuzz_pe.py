"""Mutation fuzzer for bin_scanner (PE parser + entropy scanner).

Oracles:
  - pe_parser.parse_pe() must return PEInfo or raise PEParseError *only*.
    Any other exception type is a defect (crash on malformed input).
  - entropy.entropy_score() / scan_file_entropy() must not raise for
    window_size >= 1 on arbitrary data.

Saves the first repro buffer per unique crash signature to crashes/.
Deterministic: same --seed reproduces the same campaign.

Usage:
    python tools/fuzz/fuzz_pe.py [--iters 20000] [--seed 1]
"""

import argparse
import os
import random
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from bin_scanner.pe_parser import parse_pe, PEParseError  # noqa: E402
from bin_scanner.entropy import entropy_score, scan_file_entropy  # noqa: E402

CRASH_DIR = os.path.join(os.path.dirname(__file__), 'crashes')


def make_seed_pe() -> bytes:
    """Minimal valid PE32 (mirrors tools/tests/test_pe_parser.make_minimal_pe)."""
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)
    data = dos + b'\x00' * (0x80 - len(dos))
    data += b'PE\x00\x00'
    data += struct.pack('<HHIIHHI', 0x014c, 1, 0, 0, 0, 0xE0, 0x010F)
    opt = bytearray(0xE0)
    struct.pack_into('<H', opt, 0, 0x10b)
    struct.pack_into('<I', opt, 16, 0x1000)
    struct.pack_into('<I', opt, 28, 0x400000)
    struct.pack_into('<H', opt, 68, 2)
    data += opt
    sec = bytearray(40)
    sec[0:8] = b'.text\x00\x00\x00'
    struct.pack_into('<II', sec, 8, 0x200, 0x1000)
    struct.pack_into('<II', sec, 16, 0x200, 0x200)
    struct.pack_into('<I', sec, 36, 0x60000020)
    data += sec
    return bytes(data)


def mutate(seed: bytes, rng: random.Random) -> bytes:
    buf = bytearray(seed)
    choice = rng.randrange(6)
    if choice == 0 and len(buf) > 1:
        # truncation — stresses every length guard in the parser
        del buf[rng.randrange(1, len(buf)):]
    elif choice == 1:
        # random byte flips
        for _ in range(rng.randrange(1, 9)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
    elif choice == 2:
        # interesting values into a random 2/4-byte field
        val = rng.choice([0, 1, 0x7FFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF])
        off = rng.randrange(len(buf) - 4)
        struct.pack_into('<I', buf, off, val)
    elif choice == 3:
        # e_lfanew games: near-valid and absurd PE header offsets
        struct.pack_into('<I', buf, 0x3C, rng.choice(
            [0x40, 0x3E, 0x80, 0x100, len(buf), len(buf) + 1, 0xFFFFFF00]))
    elif choice == 4:
        # optional-header magic: PE32 / PE32+ / garbage
        struct.pack_into('<H', buf, 0x98, rng.choice([0x10B, 0x20B, 0x107, 0xAAAA]))
    else:
        # append junk
        buf += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
    return bytes(buf)


def record_crashes(crashes: dict, sig: str, data: bytes):
    if sig not in crashes:
        os.makedirs(CRASH_DIR, exist_ok=True)
        path = os.path.join(CRASH_DIR, f'crash_{len(crashes):02d}.bin')
        with open(path, 'wb') as f:
            f.write(data)
        crashes[sig] = path


def fuzz_pe(iters: int, rng: random.Random) -> dict:
    crashes = {}
    for i in range(iters):
        blob = mutate(make_seed_pe(), rng)
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
        try:
            tmp.write(blob)
            tmp.close()
            parse_pe(tmp.name)  # noqa: B018 — oracle: PEParseError or return only
        except PEParseError:
            pass  # expected, healthy rejection
        except Exception as e:  # noqa: BLE001 — anything else is a defect
            sig = f'{type(e).__name__}: {e}'[:120]
            record_crashes(crashes, sig, blob)
        finally:
            os.unlink(tmp.name)
        if (i + 1) % 5000 == 0:
            print(f'  [pe] {i + 1}/{iters} iters, {len(crashes)} unique crash sigs')
    return crashes


def fuzz_entropy(iters: int, rng: random.Random) -> dict:
    crashes = {}
    for i in range(iters):
        n = rng.randrange(0, 2048)
        data = bytes(rng.randrange(256) for _ in range(n))
        window = rng.choice([1, 2, 7, 256, 4096, n, n + 1, n + 5])
        try:
            entropy_score(data, max(window, 1))
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
            tmp.write(data)
            tmp.close()
            scan_file_entropy(tmp.name, window_size=max(window, 1))
            os.unlink(tmp.name)
        except Exception as e:  # noqa: BLE001
            sig = f'{type(e).__name__}: {e}'[:120]
            record_crashes(crashes, sig, data)
        if (i + 1) % 2500 == 0:
            print(f'  [entropy] {i + 1}/{iters} iters, {len(crashes)} unique crash sigs')
    return crashes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iters', type=int, default=20000)
    ap.add_argument('--seed', type=int, default=1)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    print(f'bin_scanner fuzz campaign: seed={args.seed} pe_iters={args.iters}')

    pe_crashes = fuzz_pe(args.iters, rng)
    ent_crashes = fuzz_entropy(max(args.iters // 4, 1000), rng)

    print('\n==== RESULTS ====')
    for label, crashes in (('pe_parser', pe_crashes), ('entropy', ent_crashes)):
        print(f'{label}: {len(crashes)} unique crash signature(s)')
        for sig, path in crashes.items():
            print(f'  - {sig}   [repro: {path}]')
    if not pe_crashes and not ent_crashes:
        print('No unexpected exceptions. All malformed inputs handled cleanly.')


if __name__ == '__main__':
    main()
