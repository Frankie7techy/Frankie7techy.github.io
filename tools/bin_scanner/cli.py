"""Command-line interface for bin_scanner utilities.

Commands:
  pe <file>          Parse PE headers
  entropy <file>     Analyze entropy, report high-entropy regions
"""

import argparse
import json
import sys
from pathlib import Path

from .pe_parser import parse_pe, format_pe_info, PEParseError
from .entropy import scan_file_entropy


def cmd_pe(args):
    try:
        info = parse_pe(args.file)
        out = format_pe_info(info)
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"PE Info for {args.file}")
            print(f"  Machine: {out['machine']}")
            print(f"  Sections: {out['sections']}")
            print(f"  Entry Point RVA: {out['entry_point_rva']}")
            print(f"  Image Base: {out['image_base']}")
            print(f"  Subsystem: {out['subsystem']}")
            print(f"  Is DLL: {out['is_dll']}")
            print("  Sections:")
            for s in out['sections_detail']:
                print(f"    {s['name']:8} VA={s['virtual_address']} VS={s['virtual_size']} Raw={s['raw_data_size']} Char={s['characteristics']}")
    except PEParseError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(2)


def cmd_entropy(args):
    try:
        result = scan_file_entropy(args.file, window_size=args.window, threshold=args.threshold)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Entropy analysis for {args.file}")
            print(f"  Size: {result['file_size']} bytes")
            print(f"  Average entropy: {result['average_entropy']:.4f}")
            print(f"  Window size: {result['window_size']}")
            print(f"  Threshold: {result['threshold']}")
            print(f"  High entropy regions: {result['high_region_count']}")
            for r in result['high_entropy_regions'][:10]:
                print(f"    Offset 0x{r['offset']:X} entropy={r['entropy']:.4f}")
            if result['high_region_count'] > 10:
                print(f"    ... and {result['high_region_count']-10} more")
    except FileNotFoundError:
        print(f"Error: file not found {args.file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="Static binary analysis utilities")
    sub = parser.add_subparsers(dest='command', required=True)

    pe_parser = sub.add_parser('pe', help='Parse PE headers')
    pe_parser.add_argument('file', help='Path to PE file')
    pe_parser.add_argument('--json', action='store_true', help='Output JSON')
    pe_parser.set_defaults(func=cmd_pe)

    ent_parser = sub.add_parser('entropy', help='Analyze file entropy')
    ent_parser.add_argument('file', help='Path to file')
    ent_parser.add_argument('--window', type=int, default=4096, help='Window size in bytes')
    ent_parser.add_argument('--threshold', type=float, default=7.8, help='High entropy threshold')
    ent_parser.add_argument('--json', action='store_true', help='Output JSON')
    ent_parser.set_defaults(func=cmd_entropy)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
