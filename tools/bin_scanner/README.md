# bin_scanner - Static Binary Analysis Utilities

Defensive reverse-engineering toolkit for static analysis of Windows PE binaries and entropy-based packing detection.

## Overview

`bin_scanner` provides two core modules:

- **PE parser** (`pe_parser.py`): Safe read-only parsing of PE headers, COFF header, optional header, and section table. No execution.
- **Entropy analyzer** (`entropy.py`): Shannon entropy calculation per sliding window with high-entropy region reporting for packing/obfuscation detection.

## Installation

```bash
git clone <repo>
cd tools
python -m pip install --upgrade pip
# No external runtime dependencies; uses only Python stdlib.
python -m bin_scanner.cli --help
```

## Architecture

```
bin_scanner/
  __init__.py
  pe_parser.py      # PE header parsing, dataclass models
  entropy.py        # Shannon entropy, streaming scan
  cli.py            # argparse CLI entrypoint
tests/
  test_pe_parser.py
  test_entropy.py
```

- `parse_pe(path)` returns `PEInfo` with machine, sections, entry point, subsystem, etc.
- `scan_file_entropy(path, window_size, threshold)` returns average entropy and high-entropy regions.

## Usage

### PE Header Parsing

```bash
python -m bin_scanner.cli pe path/to/binary.exe
python -m bin_scanner.cli pe path/to/binary.exe --json
```

Example output:
```
PE Info for file.exe
  Machine: 0x14c
  Sections: 3
  Entry Point RVA: 0x1000
  Image Base: 0x400000
  Subsystem: 3
  Is DLL: False
  Sections:
    .text    VA=0x1000 VS=... Raw=... Char=0x60000020
```

### Entropy Analysis

```bash
python -m bin_scanner.cli entropy suspicious.bin --window 4096 --threshold 7.8 --json
```

High entropy (>7.8) typically indicates compressed/packed/encrypted sections.

## Unit Tests

```bash
python -m unittest discover tests
```

Tests cover minimal PE construction and entropy edge cases.

## Defensive Use Cases

- Triage malware samples for packing indicators before deeper analysis.
- Validate PE metadata integrity for forensic triage.
- Generate baseline entropy profiles for legitimate software.

## Safety

- Read-only operations only.
- No network or subprocess execution.
- Input validation with explicit PEParseError on malformed files.

## License

Research / defensive use only.
