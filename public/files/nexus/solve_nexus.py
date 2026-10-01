#!/usr/bin/env python3
"""Nexus — offline flag recovery from the official scorer's embedded rodata.

Every labeled field in nexus.bin is a decoy. The only thing that tells the
truth is `check` — the official scorer. It XOR-decodes its expected answer
with a 4-byte key hidden in .rodata, so we can recover the flag statically.
"""

import struct
import sys


def find_section(elf, wanted):
    """Walk the section header table and return (offset, size) of a section."""
    e_shoff, = struct.unpack_from('<Q', elf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', elf, 0x3A)
    shstr_off, = struct.unpack_from('<I', elf, e_shoff + e_shstrndx * e_shentsize + 0x18)
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        name_off, = struct.unpack_from('<I', elf, base)
        sh_type, = struct.unpack_from('<I', elf, base + 4)
        offset, size = struct.unpack_from('<QQ', elf, base + 0x18)
        end = elf.index(b'\0', shstr_off + name_off)
        name = elf[shstr_off + name_off:end]
        if name == wanted and sh_type == 1:  # PROGBITS
            return offset, size
    raise ValueError(f'section {wanted!r} not found')


def extract_flag(check_path='check'):
    with open(check_path, 'rb') as f:
        elf = f.read()

    ro_off, ro_size = find_section(elf, b'.rodata')
    rodata = elf[ro_off:ro_off + ro_size]

    # From the disassembly of the decode loop:
    #   1240: mov  %rax,%rcx
    #   1247: and  $0x3,%ecx              # i & 3
    #   124a: movzbl (%rdi,%rcx,1),%ecx   # rdi = key   (rodata + 0x20)
    #   124e: xor  (%rsi,%rax,1),%cl      # rsi = data  (rodata + 0x40)
    #   1255: mov  %cl,-0x1(%rdx)         # expected[i] = key[i & 3] ^ data[i]
    # and expected[0] is hardcoded to 0x72 ('r').
    key = rodata[0x20:0x24]
    payload = rodata[0x40:0x40 + 36]

    flag = bytearray(b'r')
    for i in range(1, 36):
        flag.append(key[i & 3] ^ payload[i])
    return flag.decode('ascii')


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'check'
    flag = extract_flag(path)
    print(f'Flag: {flag}')
