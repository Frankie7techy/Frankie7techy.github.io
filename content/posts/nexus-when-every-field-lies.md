---
title: "Nexus — When Every Field Lies, Trust the Scorer"
date: 2026-10-01
draft: false
description: "A custom hash chain, 8 data blocks, a 32-byte initial state — and every labeled field in the binary pointing somewhere wrong. Plus a hash chain that turns out not to exist. Reversing the only field that tells the truth: the official scorer itself."
tags: ["CTF", "Reverse Engineering", "Binary Analysis", "Crypto"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

## Challenge Overview

| Field | Value |
|---|---|
| **Platform** | AfricaHackon |
| **Challenge** | Nexus |
| **Author** | Dr Programmer |
| **Category** | Reverse Engineering |
| **Difficulty** | Hard |
| **Points** | 400 |
| **Given** | `02_NEXUS.zip` → `check`, `validator`, `nexus.bin` |

> *"A custom hash chain processor receives 8 data blocks and a 32-byte initial state. The blocks must be applied in a specific order determined by nibble-decomposition of the initial state bytes — but the binary contains a 72-byte 'decoy header' declaring a different block order (`01234567`), a 64-byte scrambled state immediately after the declared order that looks like the real initial state, and a `hash_chain_init` field containing a SHA256-transformed variant of the true init state. Players must identify the correct field layout, extract the true initial state, derive the block ordering from its nibbles, execute a custom hash chain, and XOR-decrypt the ciphertext. Every shortcut and labeled field in the binary is wrong."*

---

## TL;DR

The description reads like a spec for a hash-chain processor. It's actually a misdirection engine with a sense of humor. The intended path — extract the true init state, derive the block order from its nibbles, run the custom hash chain, XOR-decrypt the ciphertext — has a fatal flaw: **the custom hash chain is specified nowhere.** Not in the binaries (neither one even opens the file), not in the data. The one thing the intended path requires is the one thing the challenge never gives you.

Meanwhile exactly one sentence in the whole challenge tells the truth, and it's printed by the decoy tool: *"Submit to ./check for official scoring."* So `check` is the real scorer — and its "protection" is a 4-byte repeating XOR with a key sitting in plain sight in `.rodata`. Reversing that loop recovers the flag statically. No chain required.

**The five moves:**
1. Unpack the zip and map `nexus.bin`'s decoy anatomy
2. Burn an evening proving every labeled field is a lie (including the chain itself)
3. Disassemble the scorer's decode loop
4. Dodge the decoy gauntlet — the validator blesses a fake literally labeled `DECOY`
5. Recover the flag from `.rodata` and feed the real scorer

---

## Step 1 — Unpack and Smell the Story

![Extracting the challenge files and the decoy header](/public/images/nexus/01_challenge_files.png)

Three files: two tiny ELFs and a 688-byte data file. The header of `nexus.bin` sets the tone before you've parsed a single field:

```
NEXS | 01234567 | NEXUS v1.0 hash chain processor
```

A magic value, a "declared block order," a version string. The description already told me this header is a decoy — it declares the order `01234567` while the *real* order supposedly comes from nibble-decomposition of the initial state. When a binary structure announces itself this confidently, my suspicion gland starts tingling. This is the same challenge family as [Dead Reckoning](/public/posts/dead-reckoning-when-the-paperwork-lies/), and the house style is consistent: *the documentation sells you a method; the method is the trap.*

---

## Step 2 — The Field Anatomy (Every Label Is a Lie)

![The field map of nexus.bin](/public/images/nexus/02_bin_anatomy.png)

Per the description, the layout is: a 72-byte decoy header, a 64-byte scrambled state, a 32-byte `hash_chain_init` field, 8 data blocks, and a ciphertext. The arithmetic fits perfectly — 72 + 64 + 32 + 256 + 264 = 688 bytes exactly. A tidy file. A tidy lie.

Here's the part that cost me an evening. I took the intended path seriously:

- **Every 32-byte window** in the file (all 656 of them) as the true init state
- **Seven order derivations** — first-occurrence nibble dedupe, high/low nibbles, argsort, the first 8 nibbles raw, the full 64-nibble sequence
- **Seventeen chain constructions** — SHA256 chains (`state‖block`, `block‖state`, index-mixed), rotate-XOR, add/sub mixes, hash-state-XOR-block, CBC-style chaining over the ciphertext itself
- **Eight keystream expansions** — final state repeated, init repeated, SHA256 expansion, intermediate states concatenated, per-chunk mapping

Somewhere north of **five million combinations**. Result: zero printable plaintext, zero flag fragments, no repeating-XOR periodicity anywhere in the file, no hash relationships between regions. The chain that would make the intended path work simply is not in the files.

And that's the trap within the trap. The description says *"execute a custom hash chain"* — and never defines it. The intended path isn't just guarded by decoys; it's **unwalkable by design**. Every labeled field lies, and the one instruction that matters has no label at all.

---

## Step 3 — The One Honest Sentence

The `validator` greets a candidate with a warm **VALID** and prints: *"Submit to ./check for official scoring."*

That sentence is the only truth in the entire challenge — and it's printed by the decoy. I love that. The misdirection tool is honest about where the real scorer lives, because knowing *where* to submit is worthless if you can't produce the string. The challenge doesn't hide the door; it hides the key.

So: `check` is the real scorer. Let's read what it actually does.

---

## Step 4 — Disassembling the Scorer

![The XOR decode loop inside check](/public/images/nexus/03_check_disasm.png)

`check` is a ~14 KB ELF that reads a line from stdin, strips the newline, builds an expected string, and `strcmp`s your input against it. The build is the whole game:

```asm
1247: and  $0x3,%ecx              # i & 3
124a: movzbl (%rdi,%rcx,1),%ecx   # key[i & 3]   <- rdi = .rodata+0x20
124e: xor  (%rsi,%rax,1),%cl      # ^= data[i]   <- rsi = .rodata+0x40
1255: mov  %cl,-0x1(%rdx)         # expected[i]
```

Plus one instruction before the loop hardcoding `expected[0] = 0x72` — the leading `r`. From the section dump:

- **Key:** `8c 2b 97 59` at `.rodata+0x20`
- **Payload:** 36 bytes at `.rodata+0x40`

That's the entire "protection": `expected[i] = key[i & 3] ^ data[i]`, a 4-byte repeating XOR whose key ships inside the binary. The section header table will happily walk you straight to it — no symbol names, no labels, no help. The challenge's own philosophy, applied to itself: the scorer has no labels either.

---

## Step 5 — The Decoy Gauntlet

![The decoy validator blessing a flag the real scorer rejects](/public/images/nexus/04_decoy_gauntlet.png)

The `validator` deserves its own paragraph. It blesses exactly one string:

```
r00t{n3xus_DECOY_40187c7d04ac816824f4d81f}
```

A decoy that *literally self-identifies* — but only after you've fed it through, watched it print **VALID**, marched it over to `check`, and been told **WRONG**. Its XOR key is `de c0 ad be` — "deadcode," a decoy field inside a decoy tool. The gauntlet rounds out to three planted wrong answers (the header's order, the scrambled state, the validator's blessing) and one real scorer.

---

## Step 6 — The Flag

![check confirming the real flag](/public/images/nexus/05_flag_revealed.png)

```
r00t{n3xus_a5f383c453ce4d7ad21f7d6d}
```

**CORRECT** per the official scorer. The description promised that every shortcut and labeled field would be wrong — it went 4 for 4, and then the checker went the other way.

---

## Why You Should Care at 2 AM (Defender Notes)

1. **A description is not a spec.** "Execute a custom hash chain" is not an algorithm — it's a wish. If your security design depends on a step that's never defined, you haven't built protection; you've built a story about protection. In real systems this is the undocumented KDF whose parameters live in a header comment, or the "proprietary encryption" with no reference implementation.

2. **Verify the verifier.** Two scorers with two different truths is a supply-chain story in miniature. The validator blessed a string with total confidence — and total wrongness. If you don't know where your verification logic's truth comes from, you're just running someone else's bug with better UX.

3. **Every labeled field is an attack surface.** A declared block order, a "scrambled" state, a `hash_chain_init` field — each one exists to steer an analyst. Real formats have the same problem: any field an attacker can read, they can also *misread on purpose* if the format's documentation emphasizes the wrong things.

4. **The best traps aren't broken — they're under-specified.** Nothing in this challenge was corrupted or malformed. The misdirection lived entirely in what the description *emphasized* versus what the files actually contained. That's also what good incident response looks like: trust artifacts over narratives.

One custom hash chain that doesn't exist is a red herring. A custom hash chain that doesn't exist *plus* a decoy tool vouching for the wrong answer — that's a Tuesday.

---

## The Full Solver

```python
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
    shstr_off, = struct.unpack_from('<I', elf,
                                    e_shoff + e_shstrndx * e_shentsize + 0x18)
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        name_off, = struct.unpack_from('<I', elf, base)
        sh_type, = struct.unpack_from('<I', elf, base + 4)
        offset, size = struct.unpack_from('<QQ', elf, base + 0x18)
        end = elf.index(b'\0', shstr_off + name_off)
        if elf[shstr_off + name_off:end] == wanted and sh_type == 1:
            return offset, size
    raise ValueError(f'section {wanted!r} not found')


def extract_flag(check_path='check'):
    with open(check_path, 'rb') as f:
        elf = f.read()

    ro_off, ro_size = find_section(elf, b'.rodata')
    rodata = elf[ro_off:ro_off + ro_size]

    # From the decode loop:
    #   and  $0x3,%ecx              # i & 3
    #   movzbl (%rdi,%rcx,1),%ecx   # rdi = key   (rodata + 0x20)
    #   xor  (%rsi,%rax,1),%cl      # rsi = data  (rodata + 0x40)
    # plus expected[0] hardcoded to 0x72 ('r').
    key = rodata[0x20:0x24]
    payload = rodata[0x40:0x40 + 36]

    flag = bytearray(b'r')
    for i in range(1, 36):
        flag.append(key[i & 3] ^ payload[i])
    return flag.decode('ascii')


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'check'
    print(f'Flag: {extract_flag(path)}')
```

One run, no arguments, no chain:

```
$ python3 solve_nexus.py ./check
Flag: r00t{n3xus_a5f383c453ce4d7ad21f7d6d}
$ echo 'r00t{n3xus_a5f383c453ce4d7ad21f7d6d}' | ./check
CORRECT
```

---

## Recap — Five Moves

| Step | Action |
|---|---|
| 1 | Unpack the zip; read the decoy header (`NEXS` + order `01234567`) |
| 2 | Prove the intended path is unwalkable — the custom hash chain is defined nowhere |
| 3 | Follow the one honest sentence: `check` is the official scorer |
| 4 | Disassemble the decode loop: `expected[i] = key[i & 3] ^ data[i]` |
| 5 | Recover the flag from `.rodata`, reject the `DECOY` blessing |

The description promised every shortcut and labeled field would be wrong. It kept its word — all four lies landed exactly where advertised, and the unlabeled key in `.rodata` went the other way.

Trust the scorer. Read the loop.

---

*Scripts: [solve_nexus.py](/public/files/nexus/solve_nexus.py)*

*— Frank Ngaruiya (@z3r0bme)*
