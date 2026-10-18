---
title: "Wraith: Unwrapping the Bytecode VM Inside a 2 KB wasm Module"
date: 2026-10-18
draft: false
description: "A 2 KB WebAssembly file with one exported function and two imports. No strings, no symbols, nothing readable. Inside it hides a tiny bytecode VM that checks the flag one byte at a time, and every check inverts in closed form."
tags: ["CTF", "Reverse Engineering", "WebAssembly", "Bytecode VM", "Binary Analysis", "Python"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Rev</span>
    <span class="dr-badge red">Medium</span>
    <span class="dr-badge cyan">200 pts</span>
    <span class="dr-badge ghost">r00t CTF · Wraith</span>
  </div>
  <div class="dr-title">WRAITH</div>
  <p class="dr-sub">One file in the handout: <strong>wraith.wasm</strong>, two kilobytes, a single exported function called <code>check_flag</code>, and no strings worth reading. It turns out to be a <strong>stack VM running a hidden bytecode program</strong> that tests the flag one byte at a time. Every check inverts in closed form, so there is nothing to brute force.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">2 KB</span><span class="l">wasm module</span></div>
  <div class="dr-stat"><span class="n cyan">331</span><span class="l">hidden bytes</span></div>
  <div class="dr-stat"><span class="n red">29</span><span class="l">byte checks</span></div>
  <div class="dr-stat"><span class="n">0</span><span class="l">brute force</span></div>
</div>

## The handout

The zip contains exactly one file. No README, no source, no hints:

```
Wraith/
└── wraith.wasm      2094 bytes
```

`file` names it for you: a WebAssembly binary, module version 1. That is the whole challenge surface. Two kilobytes of compiled bytecode with nothing to `strings` and nothing to grep.

The first look at the structure tells the whole story:

![wasm-objdump -x on wraith.wasm, showing the imports, the check_flag export and a 347 byte rodata segment](/public/images/wraith/01_wasm_module.svg)

Read the import table. The module pulls in two host functions:

<div class="dr-callout">
  <span class="t">The two imports are the giveaway</span>
  <p>It imports <code>env.js_print_ok</code> and <code>env.js_print_fail</code>, and exports exactly one function, <code>check_flag(i32) -&gt; i32</code>. Someone compiled a flag checker to wasm and let the host JavaScript do the printing. That means the module is meant to run inside a small JS harness, so <strong>we can run it ourselves</strong> once we understand it.</p>
</div>

There is also a data segment worth noting: a 347 byte `.rodata` blob loaded at offset `1024`. That blob is the only real payload in the file, and it is not plaintext.

## The tell: a checker wearing a VM costume

Disassembling `check_flag` is where it gets fun. The function is doing something odd for a flag check. It never compares your input against a constant directly. Instead it does this:

1. Scans the input for its length (an unrolled loop looking for the first zero byte).
2. **De-obfuscates a second program** into a buffer on the stack.
3. Runs a small interpreter loop over that program, with a stack, a stack pointer and a halt flag.

In other words, `check_flag` is not the check. It is a **virtual machine**, and the check is a bytecode program hidden inside `.rodata`.

![The Wraith pipeline: triage, de-obfuscate, decode the VM, invert the checks, verify](/public/images/wraith/00_chain.svg)

Once you see the interpreter shape, the path is fixed. Recover the program, read the opcodes, invert the comparisons. Let me take each step in turn.

## Step 1: De-obfuscate the hidden program

The module builds the real program by XORing the `.rodata` blob against a short repeating key. The code is specific about which bytes it uses:

```
key[i] = rodata[i & 2]           # only ever 2 values: rodata[0] or rodata[2]
prog[j] = rodata[16 + j] XOR key[j % 4]     # for every byte of the program
```

The first sixteen bytes of `.rodata` are the key material (four bytes repeated), and the actual payload starts at byte sixteen. The de-obfuscation key is `90 63 09 d2`, recovered straight from the blob, and the program comes out at 331 bytes:

![The de-obfuscated 331 byte program, showing the push/xor/rotl/eq shape of each check](/public/images/wraith/02_program_decoded.svg)

Now the program is readable, and it has a very regular shape.

## Step 2: Read the bytecode

The interpreter is a textbook stack machine. I mapped every opcode by reading the dispatch loop in the WAT. The comparison is a single byte subtracted from `'A'` (0x41) feeding a jump table, so the opcodes land neatly in the `A` to `H` range, plus two special bytes:

| Opcode | Byte | Meaning |
|---|---|---|
| `A` | `0x41` | push immediate (next byte) |
| `B` | `0x42` | push `input[idx]` (next byte is the index) |
| `C` | `0x43` | xor top two, push result |
| `D` | `0x44` | add immediate to top |
| `E` | `0x45` | rotate top left by immediate (mod 8) |
| `F` | `0x46` | compare top two, push `1` or `0` |
| `G` | `0x47` | and top two, push result |
| `H` | `0x48` | halt, return top of stack |
| `0xDE` | | group separator (no-op) |
| `0xAD` | | padding (no-op, skips a byte) |

With the table in hand, the program describes itself. It is **ten groups of three checks**, then a padding byte, then a folding `and` for every result, then `halt`:

```
de                      ; group separator
42 00 41 c2 43 45 07 41 58 46    ; check byte 0
42 01 41 a4 43 45 04 41 49 46    ; check byte 1
42 02 41 fb 43 45 06 41 f2 46    ; check byte 2
...
47 47 47 47 ... 47      ; and every result together (x28)
48                      ; halt, the result is the AND of all 29 checks
```

Every check has the same ten byte form:

```
push input[i]     ; B idx
push k            ; A k
xor               ; C
rotl r            ; E r
push c            ; A c
eq                ; F
```

So for each index `i`, the program computes:

```
rol8( input[i] XOR k , r )  ==  c
```

and then ANDs all 29 boolean results together. The flag is accepted only if **every** check passes. There are 29 checks, so the flag is 29 bytes.

## Step 3: Invert the checks

This is the moment the challenge collapses. There is no chaining between checks, no feedback, no state carried from one byte to the next. Each of the 29 comparisons stands alone, and it is a byte-level equation you can solve on paper:

```
rol8( input[i] XOR k , r ) == c
```

Rotate the other way, undo the XOR, and you have each byte in closed form:

```
input[i] = ror8(c, r) XOR k
```

Two operations per byte. No solver, no SAT, no brute force. The whole thing is:

```python
#!/usr/bin/env python3
"""Pull the bytecode out of wraith.wasm, read each check, invert it."""
data = open("Wraith/wraith.wasm", "rb").read()

# 1. the 347-byte .rodata blob starts right after "i32.const 1024" (0x41 0x80 0x08 0x0b)
needle = bytes([0x41, 0x80, 0x08, 0x0b])
p = data.find(needle) + len(needle)

# LEB128 length prefix, then the blob
size, shift = 0, 0
while True:
    b = data[p]; p += 1
    size |= (b & 0x7f) << shift
    if not (b & 0x80):
        break
    shift += 7
rodata = data[p:p + size]

# 2. program = rodata[16:] XOR a repeating 4-byte key from rodata[0:4]
key = rodata[:4]
prog = bytes(b ^ key[i % 4] for i, b in enumerate(rodata[16:16 + 331]))

# 3. each check is 10 bytes: B idx, A k, C, E r, A c, F
def ror8(v, r):
    r &= 7
    return ((v >> r) | (v << ((8 - r) & 7))) & 0xff

flag = bytearray()
i = 0
while i < len(prog):
    if (prog[i] == 0x42 and prog[i + 2] == 0x41 and prog[i + 4] == 0x43
            and prog[i + 5] == 0x45 and prog[i + 7] == 0x41 and prog[i + 9] == 0x46):
        idx, k, r, c = prog[i + 1], prog[i + 3], prog[i + 6], prog[i + 8]
        flag.append(ror8(c, r) ^ k)
        i += 10
    else:
        i += 2 if prog[i] in (0x41, 0x42, 0x44, 0x45, 0xad) else 1

print(bytes(flag).decode())
```

Run it and the bytes fall out in order:

```
r00t{w4sm_vm_byp4ss_unl0ck3d}
```

## Step 4: Prove it in a real engine

A recovered flag from my own reimplementation is nice, but I want the actual `.wasm` to agree, not just my model of it. The module needs a host for its two imports, which is exactly what a wasm engine gives us. I loaded the binary with **wasmtime**, stubbed `js_print_ok` and `js_print_fail` to record which one fires, wrote the candidate into the module's linear memory, and called `check_flag`:

![Calling check_flag in wasmtime with the real flag and three wrong candidates](/public/images/wraith/03_engine_verify.svg)

The real flag returns `1` and calls `js_print_ok`. A one-bit change, a string of `A`s, and the empty string all return `0` and call `js_print_fail`. The compiled artifact and my inversion agree byte for byte.

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{w4sm_vm_byp4ss_unl0ck3d}</code>
</div>

## The traps, and what they teach

This challenge is friendly once you spot the VM, but there are a few places to lose an evening.

<div class="dr-traps">
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> Treating it as crypto</span>
    An XOR plus a rotate looks cipher-ish, so the instinct is to reach for a keystream or a differential. It is neither. Each byte is an independent equation with a known answer, so you invert instead of attack.
    <span class="truth">it is a lookup, not a cipher</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> Reading .rodata as text</span>
    The blob is obfuscated, so `strings` and hexdumps show noise. The plaintext is the de-obfuscated <em>program</em>, not the blob, and it never appears as a string at all.
    <span class="truth">the payload is a program, not a message</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> Getting the rotate backwards</span>
    The VM encodes `rol8` and you must apply `ror8` to invert it. Rotate the wrong way and you get a plausible-looking but wrong byte, which is the most annoying kind of wrong.
    <span class="truth">invert the direction, always</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> Forgetting the length gate</span>
    The input buffer is zero-filled past its real end, so a short flag fails the later checks with `0` bytes rather than crashing. The flag is exactly 29 bytes because there are 29 checks.
    <span class="truth">29 checks means 29 bytes</span>
  </div>
</div>

## Takeaway

Wraith is a nice reminder that "compiled binary" does not mean "opaque binary". Two kilobytes of wasm, no symbols and no strings, and the entire security model still came down to a handful of invertible byte operations that a forty line script undoes.

- **Look at the imports and exports first.** `js_print_ok` / `js_print_fail` told me this was a self-contained checker I could run, long before I understood a single opcode.
- **Recognise the interpreter shape.** A stack, a stack pointer, a halt flag and a jump table are the signature of a VM, and a VM usually means a hidden program you can recover instead of reverse.
- **Invert, do not brute force.** When each check is independent and closed form, the flag falls out in one pass.
- **Trust but verify.** Reimplementing the check is not proof. Running the artifact in a real engine against three wrong candidates is.

For anyone building something similar: obfuscating a checker buys you time, not security. A determined reader recovers the program, reads the opcodes and inverts the comparisons. If a value has to stay secret, keep it out of the client entirely.

<div class="dr-chips">
  <span class="dr-chip">WebAssembly</span><span class="dr-chip">wasm2wat</span><span class="dr-chip">wasm-objdump</span><span class="dr-chip">wasmtime</span><span class="dr-chip">stack VM</span><span class="dr-chip">bytecode</span><span class="dr-chip">XOR + rol8</span>
</div>

*Solved on the r00t CTF platform. Challenge: Wraith by k4p3re. Full solver and decoder scripts available on request.*
