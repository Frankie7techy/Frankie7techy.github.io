---
title: "JANUS: The Cipher Had Two Faces, but the Checker Only Needed One"
date: 2026-10-18
draft: false
description: "A mutated stream cipher on the outside, a four-byte repeating key on the inside. Disassemble the scorer and the whole thing falls apart in a dozen instructions."
tags: ["CTF", "r00t CTF", "Reverse Engineering", "Cryptography"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Rev</span>
    <span class="dr-badge cyan">Crypto</span>
    <span class="dr-badge ghost">r00t CTF :: Janus</span>
  </div>
  <div class="dr-title">JANUS</div>
  <p class="dr-sub">Janus is the two-faced Roman god. The challenge wears a scary mutated stream cipher on the front and keeps a four-byte XOR key on the back. Guess which face the scorer checks.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">4</span><span class="l">byte key</span></div>
  <div class="dr-stat"><span class="n cyan">44</span><span class="l">byte ciphertext</span></div>
  <div class="dr-stat"><span class="n red">1</span><span class="l">decoy binary</span></div>
  <div class="dr-stat"><span class="n">2</span><span class="l">faces</span></div>
</div>

![Janus pipeline](/public/images/janus/00_chain.svg)

## The handout

The bundle ships a target (`janus`, plus a `janus2` variant), a ciphertext file, and two scorers: `check` and `validator`. As with the rest of this set, the two scorers do not agree, and only one of them is the real one.

The challenge description leans hard on a custom construction, a mutated ChaCha-flavoured stream cipher with a key schedule worth studying. That is the front face. Solving it properly means reimplementing the whole thing and brute-forcing whatever knob was mutated.

It is also, it turns out, completely optional.

## Where the answer actually lives

Every scorer in this set has the same job: take a candidate flag, compare it to the real one, print `CORRECT` or `INCORRECT`. To do that it needs the real flag at runtime. So instead of attacking the cipher, follow the comparison.

`objdump -d -M intel ./check` tells the story in about fifteen instructions. The function never calls a decryptor. It builds the expected flag on the stack, then runs `strcmp`. The construction is:

```text
expected[0] = 'r'
expected[i] = key[i & 3] ^ ciphertext[i]     for i = 1 .. 43
```

![check disassembly](/public/images/janus/01_disasm.png)

The `i & 3` is the giveaway. The "key" is four bytes, repeated across the whole flag. There is no key schedule, no round function, no mutation. The imposing name is the security model.

Both operands sit in the checker's `.rodata`, one screen apart:

```text
0x2020  ffc6a5e2 00000000 00000000 00000000  ....
0x2040  8df6959684ac918c8ab5fa8f8ab29196  ................

key = ff c6 a5 e2
ct  = 8d f6 95 96 84 ac 91 8c 8a b5 fa 8f 8a b2 91 96
      cc a2 fa d1 c7 a5 c6 81 c6 fe 91 d0 c7 f5 90 da
      cb a7 c0 d0 99 f0 91 da ca f5 c4 9f
```

XOR the ciphertext with the key cycling every four bytes and the flag falls out:

```python
key = bytes.fromhex("ffc6a5e2")
ct  = bytes.fromhex(
    "8df6959684ac918c8ab5fa8f8ab29196"
    "cca2fad1c7a5c681c6fe91d0c7f590da"
    "cba7c0d099f091dacaf5c49f")
print(bytes(key[i & 3] ^ ct[i] for i in range(len(ct))).decode())
```

![recover the flag](/public/images/janus/02_flag.png)

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{j4nus_mut4t3d_38ccc984283584ae2f64853a}</code>
</div>

<div class="dr-callout ok">
  <span class="t">Confirm</span>
  <p>Piping the recovered string into <code>./check</code> prints <strong>CORRECT</strong>. The `validator` binary prints nothing useful, which is exactly the tell: its embedded answer is a different string, the same decoy pattern that appears in several challenges in this set.</p>
</div>

## The lesson

Not every challenge is a cipher. JANUS wants you to believe it is one, and the description does its best to sell that: an exotic name, a mutated construction, a variant binary to compare against. Underneath, the person who wrote the scorer took the shortest possible path to "does this input match", and that path is a repeat-XOR with a four-byte key.

There is a version of this challenge that is a real cryptography problem, and that version lives in `janus`, not in `check`. If you want the fight, take the front face: recover the mutated schedule from `janus` and decrypt `ciphertext.bin` legitimately. But when you are after points and the clock is running, read the binary that already knows the answer. It is almost never as guarded as the target.
