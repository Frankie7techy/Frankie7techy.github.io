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
    sec[0:8] = b'.text\x00\x00\x00'
    struct.pack_into('<II', sec, 8, 0x200, 0x1000)  # VirtualSize, VirtualAddress
    struct.pack_into('<II', sec, 16, 0x200, 0x200)  # SizeOfRawData, PointerToRawData
    # Characteristics at offset 36 (4 bytes)
    struct.pack_into('<I', sec, 36, 0x60000020)
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

    def _assert_truncated_optional_header_raises(self, magic):
        # opt_offset = 0x98 for the seed; the old length guard (+24) let
        # buffers of 176..183 bytes through, then struct.unpack_from crashed
        # on the image_base read. Raise PEParseError instead.
        pe = bytearray(make_minimal_pe())
        struct.pack_into('<H', pe, 0x98, magic)
        for cut in (176, 180, 183):
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(bytes(pe[:cut]))
                name = tf.name
            try:
                with self.assertRaises(PEParseError, msg=f'truncated at {cut}'):
                    parse_pe(name)
            finally:
                os.unlink(name)

    def test_truncated_optional_header_pe32(self):
        self._assert_truncated_optional_header_raises(0x10B)

    def test_truncated_optional_header_pe32_plus(self):
        self._assert_truncated_optional_header_raises(0x20B)


if __name__ == '__main__':
    unittest.main()
