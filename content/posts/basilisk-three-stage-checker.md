---
title: "Basilisk: A Three-Stage Checker and the One Byte That Undid It"
date: 2026-10-18
draft: false
description: "Three stages, a SHA-256 key schedule, a fake core dump and a GDB stub that lies about the math. The maze is real. The scorer at the end leaves the front door open."
tags: ["CTF", "r00t CTF", "Reverse Engineering", "Binary"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Rev</span>
    <span class="dr-badge red">Medium</span>
    <span class="dr-badge ghost">r00t CTF :: Basilisk</span>
  </div>
  <div class="dr-title">BASILISK</div>
  <p class="dr-sub">A checker built like an onion: three stages, a SHA-256 key schedule, a fake core dump and a two-faced GDB stub. The maze is real. The scorer at the end leaves the front door open.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">3</span><span class="l">stages</span></div>
  <div class="dr-stat"><span class="n red">5</span><span class="l">decoys</span></div>
  <div class="dr-stat"><span class="n cyan">0x5c</span><span class="l">the XOR</span></div>
  <div class="dr-stat"><span class="n">39</span><span class="l">hidden bytes</span></div>
</div>

![Basilisk pipeline](/public/images/basilisk/00_chain.svg)

## The handout

| File | What it looks like |
|---|---|
| `basilisk` | the target. A three-stage protector with anti-debug checks |
| `check` | the scorer. Feed it a flag, it says CORRECT or INCORRECT |
| `validator` | a second scorer. Its answer disagrees with `check` |
| `fake_dump.bin` | a "captured memory region from a previous run" |
| `memory_layout.txt` | a map of where the encrypted stages live |
| `debug_stub.py` | a GDB script that extracts the stages at runtime |

This is a lot of material for one challenge, and almost all of it is there to keep you busy, so let us separate the signal from the noise first.

## What Basilisk pretends to be

`memory_layout.txt` lays out a tidy three-stage design:

```text
.rodata layout (offsets from section start):
  +0x000  [16 bytes]  stage1_key_enc   XOR-obfuscated Stage 1 key
  +0x010  [32 bytes]  stage1_blob      Stage 1 encrypted payload
  +0x030  [64 bytes]  stage2_blob      Stage 2 encrypted payload (flag)

Decryption procedure:
  stage1_key  = XOR(stage1_key_enc, 0x41)
  expected    = XOR(stage1_blob, stage1_key)
  stage2_key  = SHA256(expected)[:16]
  flag_str    = XOR(stage2_blob, stage2_key)
```

Decode the key, XOR the first blob, hash the result, XOR the second blob. On paper it is a clean, fully-specified pipeline. In practice the offsets point at the wrong part of the real binary and the derivation does not land on anything printable no matter which of the obvious variants you try.

<div class="dr-callout warn">
  <span class="t">The stub admits it</span>
  <p><code>debug_stub.py</code> automates a GDB dump of the stage buffers, and its own comment warns that <strong>using all 32 bytes for the second key is wrong</strong>. When the handout's own cheating tool says its documentation is misleading, that is the challenge telling you to stop reading and start stepping.</p>
</div>

## The traps

Almost every artifact in the bundle is a fork that leads to another fork.

<div class="dr-traps">
  <div class="dr-trap">
    <span class="t"><span class="x">x</span> fake_dump.bin</span>
    A "captured memory region from a previous run". The layout notes are written as if their offsets index this dump, but they do not line up. The real stage bytes live in `basilisk` itself.
    <span class="truth">the dump is scenery</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">x</span> the 0x41 stage key</span>
    `stage1_key = XOR(stage1_key_enc, 0x41)` is spelled out in the notes. Run it and the "expected passphrase" that falls out is control bytes, not text. The tidy schedule never actually reproduces the flag.
    <span class="truth">the layout is a decoy</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">x</span> debug_stub.py</span>
    A GDB automation that claims to pull the decrypted stages out of a live process. Its own comment says key derivation number two is wrong if you feed it the full 32 bytes.
    <span class="truth">even the helper lies</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">x</span> validator</span>
    A second binary that also accepts a flag. Its embedded answer disagrees with `check`, so whatever it is validating, it is not this challenge.
    <span class="truth">trust <code>check</code></span>
  </div>
</div>

Five files, four rabbit holes. The fifth file is the one that decides the points.

## The move that mattered

The one file that actually decides whether you get points is `check`. It is small, it is not obfuscated, and it has to compare your input against the real flag to do its job. So the flag has to be inside it somewhere.

Binary authors usually do not want a plain ASCII flag sitting in `.rodata`, so they apply something cheap. Here it is the cheapest thing there is: every byte of the flag is XORed with `0x5c`.

![check rodata](/public/images/basilisk/01_rodata.png)

A three-line scanner finds it. Walk the binary, XOR a window with `0x5c`, and look for the tell-tale prefix:

```python
data = open("check", "rb").read()
for off in range(len(data) - 64):
    cand = bytes(b ^ 0x5c for b in data[off:off + 64])
    if cand.startswith(b"r00t{"):
        print(hex(off), cand.split(b"\x00")[0].decode())
```

It fires once, at file offset `0x2020`:

```text
0x2020  r00t{b4s1l1sk_d971a07f0c8349b1804cf93c}
```

No debugger, no anti-debug bypass, no SHA-256. Just one pass over the bytes and a constant that turns out to be the same `0x5c` used across several of the r00t checkers.

![flag](/public/images/basilisk/02_flag.png)

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{b4s1l1sk_d971a07f0c8349b1804cf93c}</code>
</div>

## What the challenge is really teaching

Basilisk is a lesson in picking your counter-authority. The fascinating three-stage design lives in the *target*, and it is genuinely well built. But the *scorer* is the ground truth, and a scorer only needs to know the answer. If the answer is stored with a school-project XOR, the maze is decoration.

Two habits paid off here, and they pay off on almost every binary challenge:

- Read the scorer, not just the target. The target defends itself. The scorer has no reason to.
- When a handout ships a helper script, treat its comments as evidence about the author, not as documentation.

The fun footnote: `check` has no `CORRECT` string of its own. It prints `CORRECT` by pointing six bytes into the string `INCORRECT`. The word was hiding in plain sight the whole time, which is a pretty good summary of this challenge.
