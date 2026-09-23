"""PE header parser for Windows Portable Executables.

Provides safe, read-only parsing of DOS header, PE signature, COFF header,
Optional header, and section table. No execution is performed.

Usage:
    from bin_scanner.pe_parser import parse_pe
    info = parse_pe(path)
"""

import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_data_offset: int
    raw_data_size: int
    characteristics: int


@dataclass
class PEInfo:
    machine: int
    number_of_sections: int
    time_date_stamp: int
    entry_point_rva: int
    image_base: int
    subsystem: int
    dll_characteristics: int
    sections: List[Section] = field(default_factory=list)
    is_dll: bool = False


class PEParseError(Exception):
    pass


def _read_cstring(data: bytes, offset: int, max_len: int = 256) -> str:
    end = data.find(b'\x00', offset, offset + max_len)
    if end == -1:
        end = offset + max_len
    return data[offset:end].decode('utf-8', errors='replace')


def parse_pe(file_path: str | Path) -> PEInfo:
    path = Path(file_path)
    if not path.is_file():
        raise PEParseError(f"File not found: {path}")

    with path.open('rb') as f:
        data = f.read()

    # DOS header
    if len(data) < 64 or data[:2] != b'MZ':
        raise PEParseError("Not a valid DOS MZ header")

    e_lfanew_offset = 0x3C
    if len(data) < e_lfanew_offset + 4:
        raise PEParseError("File too short for e_lfanew")
    e_lfanew = struct.unpack_from('<I', data, e_lfanew_offset)[0]

    # PE signature
    pe_sig_offset = e_lfanew
    if len(data) < pe_sig_offset + 4:
        raise PEParseError("File too short for PE signature")
    if data[pe_sig_offset:pe_sig_offset+4] != b'PE\x00\x00':
        raise PEParseError("Invalid PE signature")

    # COFF header
    coff_offset = pe_sig_offset + 4
    if len(data) < coff_offset + 20:
        raise PEParseError("File too short for COFF header")
    machine, num_sections, time_date_stamp, _, _, size_of_optional_header, characteristics = struct.unpack_from(
        '<HHIIHHI', data, coff_offset
    )

    # Optional header
    opt_offset = coff_offset + 20
    # image_base is read at opt_offset+28 (PE32) or as a qword at
    # opt_offset+24 (PE32+), so the guard must cover through opt_offset+32.
    if len(data) < opt_offset + 32:
        raise PEParseError("File too short for Optional header")

    magic = struct.unpack_from('<H', data, opt_offset)[0]
    if magic != 0x10b and magic != 0x20b:
        raise PEParseError(f"Unsupported Optional header magic: {hex(magic)}")

    # Parse relevant fields from Optional header (PE32)
    entry_point_rva = struct.unpack_from('<I', data, opt_offset + 16)[0]
    image_base = struct.unpack_from('<I', data, opt_offset + 28)[0] if magic == 0x10b else struct.unpack_from('<Q', data, opt_offset + 24)[0]
    # Subsystem at offset 68 for PE32, 70 for PE32+
    subsystem_offset = opt_offset + 68 if magic == 0x10b else opt_offset + 70
    subsystem = struct.unpack_from('<H', data, subsystem_offset)[0] if len(data) >= subsystem_offset + 2 else 0
    dll_characteristics_offset = opt_offset + 66 if magic == 0x10b else opt_offset + 68
    dll_characteristics = struct.unpack_from('<H', data, dll_characteristics_offset)[0] if len(data) >= dll_characteristics_offset + 2 else 0

    # Sections
    sections_offset = opt_offset + size_of_optional_header
    sections = []
    for i in range(num_sections):
        sec_off = sections_offset + i * 40
        if len(data) < sec_off + 40:
            break
        name_bytes = data[sec_off:sec_off+8]
        name = name_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
        virtual_size, virtual_address, raw_data_size, raw_data_offset, _, _, _, characteristics_sec = struct.unpack_from(
            '<IIIIIHHI', data, sec_off + 8
        )
        sections.append(Section(
            name=name,
            virtual_size=virtual_size,
            virtual_address=virtual_address,
            raw_data_size=raw_data_size,
            raw_data_offset=raw_data_offset,
            characteristics=characteristics_sec
        ))

    is_dll = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL

    return PEInfo(
        machine=machine,
        number_of_sections=num_sections,
        time_date_stamp=time_date_stamp,
        entry_point_rva=entry_point_rva,
        image_base=image_base,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        sections=sections,
        is_dll=is_dll
    )


def format_pe_info(info: PEInfo) -> Dict:
    return {
        'machine': hex(info.machine),
        'sections': info.number_of_sections,
        'entry_point_rva': hex(info.entry_point_rva),
        'image_base': hex(info.image_base),
        'subsystem': info.subsystem,
        'is_dll': info.is_dll,
        'sections_detail': [
            {
                'name': s.name,
                'virtual_address': hex(s.virtual_address),
                'virtual_size': s.virtual_size,
                'raw_data_size': s.raw_data_size,
                'characteristics': hex(s.characteristics)
            } for s in info.sections
        ]
    }
