---
title: "THORNWALL: Anti-Debug Theatre and a Scorer That Talks"
date: 2026-10-18
draft: false
description: "A protector that checks for TracerPid, hashes its own code, and threatens a trap path if you patch a single byte. Then the official scorer hands you the flag under a one-byte XOR."
tags: ["CTF", "r00t CTF", "Reverse Engineering", "Anti-Debug"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Rev</span>
    <span class="dr-badge red">Medium</span>
    <span class="dr-badge ghost">r00t CTF :: Thornwall</span>
  </div>
  <div class="dr-title">THORNWALL</div>
  <p class="dr-sub">A wall of thorns: a TracerPid check, a self-integrity hash, and a documented trap path if you touch a single byte of code. The scorer walks around all of it.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n red">2</span><span class="l">anti-debug layers</span></div>
  <div class="dr-stat"><span class="n">7</span><span class="l">rotation constant</span></div>
  <div class="dr-stat"><span class="n cyan">0x5c</span><span class="l">the XOR</span></div>
  <div class="dr-stat"><span class="n">0</span><span class="l">bytes patched</span></div>
</div>

![Thornwall pipeline](/public/images/thornwall/00_chain.svg)

## The handout

| File | Role |
|---|---|
| `thornwall` | the protected target |
| `check` | the scorer that decides the points |
| `validator` | a decoy scorer with a different answer |
| `bypass_guide.txt` | a walkthrough of the protection scheme |
| `thorn_reference.py` | a Python "reference" of the cipher, marked as a trap |

The interesting tension is right there in the file list: the challenge hands you a *guide* to disabling its own protection, and also warns you that following it is a trap. A self-integrity check means any byte you flip to defeat the TracerPid test will change the code hash and trip the trap path. You cannot patch your way in.

## The protector

`bypass_guide.txt` describes the wall honestly enough:

- an anti-debug check that reads `/proc/self/status` for a non-zero `TracerPid`
- a self-CRC over a region of `.text`
- a stream cipher labelled `THORN32` with a rotation constant of `7` feeding the real check

The intended path is to leave the code untouched, defeat the debugger detection by other means, and reimplement `THORN32` correctly (the shipped `thorn_reference.py` gets the rotation wrong on purpose). That is a real afternoon of work, and the trap path is unforgiving.

## The turn

Here is the thing about a wall: you do not have to climb it. You only have to reach the thing behind it, and the thing behind it is `check`.

Just like its siblings, `check` stores the expected flag in `.rodata`, obfuscated with a single-byte XOR of `0x5c`. There is no TracerPid check, no CRC, no thorn. Walk the bytes and XOR:

```python
data = open("check", "rb").read()
for off in range(len(data) - 64):
    cand = bytes(b ^ 0x5c for b in data[off:off + 64])
    if cand.startswith(b"r00t{"):
        print(hex(off), cand.split(b"\x00")[0].decode())
```

At offset `0x2020`:

```text
r00t{th0rnw4ll_8fb4b14340c6429aa81ce831}
```

![flag](/public/images/thornwall/01_flag.png)

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{th0rnw4ll_8fb4b14340c6429aa81ce831}</code>
</div>

<div class="dr-verdict">
  <div class="half auth"><span class="big">check</span><br/>CORRECT</div>
  <div class="half ghosts"><span class="big">validator</span><br/>r00t{th0rnw4ll_96eee6665a2d6db321317ef3} :: decoy</div>
</div>

## The lesson

THORNWALL is a well-built lock on a door that has no wall next to it. The protection is genuine and the guide is a trap, but the scorer was written for convenience, not for secrecy, and convenience wins every audit:

- The target defends itself because the author thought about the attacker.
- The scorer never did, because the author thought the target was enough.

When a challenge ships two binaries, figure out which one is allowed to know the answer, and read that one first. Here it saved a debugger, an anti-debug bypass, a CRC-aware patch, and a cipher reimplementation. Not every challenge needs all that. Some challenges just need one pass over `.rodata` with the right constant.
