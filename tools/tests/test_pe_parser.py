import unittest
import struct
import tempfile
import os
from bin_scanner.pe_parser import parse_pe, PEParseError


def make_minimal_pe():
    # Build a minimal valid PE in memory
    # DOS header
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    e_lfanew = 0x80
    struct.pack_into('<I', dos, 0x3C, e_lfanew)
    # Pad to e_lfanew
    data = dos + b'\x00' * (e_lfanew - len(dos))
    # PE signature
    data += b'PE\x00\x00'
    # COFF header: Machine=0x014c, Sections=1, TimeDate=0, Sym=0, Size=0, OptHeader=0xE0, Char=0x010F
    coff = struct.pack('<HHIIHHI', 0x014c, 1, 0, 0, 0, 0xE0, 0x010F)
    data += coff
    # Optional header minimal PE32 0xE0 bytes
    opt = bytearray(0xE0)
    struct.pack_into('<H', opt, 0, 0x10b)   # Magic
    struct.pack_into('<I', opt, 16, 0x1000) # EntryPoint
    struct.pack_into('<I', opt, 28, 0x400000) # ImageBase
    struct.pack_into('<H', opt, 68, 2)      # Subsystem
    data += opt
    # Section header 40 bytes
    sec = bytearray(40)
    sec[0:8] = b'.text\x00\x00'
    struct.pack_into('<II', sec, 8, 0x200, 0x1000)  # VirtualSize, VirtualAddress
    struct.pack_into('<II', sec, 16, 0x200, 0x200)  # SizeOfRawData, PointerToRawData
    struct.pack_into('<I', sec, 36, 0x60000020)     # Characteristics
    data += sec
    return bytes(data)


class TestPEParser(unittest.TestCase):
    def test_parse_minimal_pe(self):
        pe_bytes = make_minimal_pe()
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(pe_bytes)
            name = tf.name
        try:
            info = parse_pe(name)
            self.assertEqual(info.machine, 0x014c)
            self.assertEqual(info.number_of_sections, 1)
            self.assertEqual(info.entry_point_rva, 0x1000)
            self.assertEqual(info.image_base, 0x400000)
            self.assertEqual(len(info.sections), 1)
            self.assertEqual(info.sections[0].name, '.text')
        finally:
            os.unlink(name)

    def test_invalid_pe(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b'NOT A PE')
            name = tf.name
        try:
            with self.assertRaises(PEParseError):
                parse_pe(name)
        finally:
            os.unlink(name)


if __name__ == '__main__':
    unittest.main()
