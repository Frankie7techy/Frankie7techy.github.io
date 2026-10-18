---
title: "The Signal Key: Hermes Hides in the Bundle"
date: 2026-10-18
draft: false
description: "A React Native app gates a licence screen behind a string table, a rotator and a small block cipher. Everything needed to reproduce it ships inside index.android.bundle."
tags: ["CTF", "r00t CTF", "Mobile", "Reverse Engineering", "JavaScript"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Mobile</span>
    <span class="dr-badge cyan">Rev</span>
    <span class="dr-badge ghost">r00t CTF :: The Signal Key</span>
  </div>
  <div class="dr-title">THE SIGNAL KEY</div>
  <p class="dr-sub">A licence screen, a string table that rotates on boot, and a small cipher. No device, no emulator, no Frida. The whole secret is sitting in the shipped JavaScript bundle.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">14</span><span class="l">string-table entries</span></div>
  <div class="dr-stat"><span class="n cyan">11</span><span class="l">left rotations</span></div>
  <div class="dr-stat"><span class="n">4</span><span class="l">cipher rounds</span></div>
  <div class="dr-stat"><span class="n red">0</span><span class="l">devices needed</span></div>
</div>

![The Signal Key pipeline](/public/images/the-signal-key/00_chain.svg)

## The handout

One file: a React Native JavaScript bundle. React Native apps ship their logic as JavaScript, and this one was not minified into oblivion, which is the first break. The interesting code sits near the licence logic:

```javascript
var __STR_ARR = ["T2xmaHF2aCN5aHVsaWxoZw==", "T3JkZ2xxajExMQ==", ...];
__STR_ARR = rotator(__STR_ARR, ++cnt);        // cnt is 11 by the time we get here

function __sidx(i) {
  var raw = __b64d(__STR_ARR[i - 336]);
  return String.fromCharCode(...[...raw].map(b => b.charCodeAt(0) - 3));
}

var key = __sidx(342);
var ct  = __hex2bytes(__sidx(343));
var ok  = __cipherDecode(ct, key);
```

Three layers, all local: a base64 string table, a boot-time rotation of that table, and a per-character offset of `-3`.

![bundle strings](/public/images/the-signal-key/01_bundle.png)

## Layer one: un-rotate the table

The table is shuffled once at startup with `rotator(__STR_ARR, cnt)`, and `cnt` is incremented elsewhere in the boot path. By the time the licence code runs, `cnt` is `11`, so the table has been left-rotated eleven times.

```python
ARR = [...]
rot = ARR[:]
for _ in range(11):
    rot.append(rot.pop(0))
ARR = rot
```

Now `__sidx` can resolve indices. Note the off-by-336: the source indexes into the rotated global array, but the table only has fourteen entries, so the effective local index is `i - 336`.

## Layer two: decode the strings

`__sidx` base64-decodes the chosen entry, then shifts every character down by three. Two of the decodes tell you the app is real:

```text
__sidx(336) = "Activate License"
__sidx(337) = "Enter activation code"
```

And the two the cipher uses:

```text
__sidx(342) = "dojo-signal-key!"          # the key
__sidx(343) = "3be94dfe52cf7bceef6d1218214a6a6d572fe857c230d0d7c2c48adc11298388"   # the ciphertext, hex
```

## Layer three: the cipher

`__cipherDecode` runs four rounds in reverse. Each round does three things to every byte:

1. rotate right by `(round + 1) % 8`
2. subtract `(round * 7 + 1)` modulo 256
3. XOR with the key, aligned at `(i + round) % len(key)`

All three operations are reversible, and the function is already written as a *decode*, so reimplementing it in Python is mechanical:

```python
def cipher_decode(data, key):
    out = bytearray(data)
    for r in range(3, -1, -1):
        shift = (r + 1) % 8
        for i in range(len(out)):
            b = out[i]
            out[i] = ((b >> shift) | (b << (8 - shift))) & 0xFF
        for i in range(len(out)):
            k = key[(i + r) % len(key)]
            out[i] = (out[i] - (r * 7 + 1) + 256) % 256
            out[i] ^= k
    return bytes(out)

key = b"dojo-signal-key!"
ct  = bytes.fromhex("3be94dfe52cf7bceef6d1218214a6a6d572fe857c230d0d7c2c48adc11298388")
print(cipher_decode(ct, key).decode())
```

![flag](/public/images/the-signal-key/02_flag.png)

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{h3rm3s_h1d3s_1n_th3_bundl3}</code>
</div>

## Why this one is a nice challenge

There is no shortcut here, and no scorer to shortcut. The key, the ciphertext and the algorithm are all in the bundle, and the bundle is plain JavaScript, so the only way through is to actually read the code and rebuild the routine. The `-3` offset and the boot-time rotation are just enough friction to make you slow down and prove you understood the control flow instead of copying constants.

The name is a joke that lands once you see it. React Native runs its JavaScript on an engine called **Hermes**, and Hermes compiles the JavaScript into a bytecode bundle. The flag says Hermes hides in the bundle, and Hermes, here, really did. The string table, the rotation and the cipher are all sitting in the open, compiled down and shipped to every device that installs the app.

If you want a tool-based version of the same idea, the workflow is: pull `index.android.bundle` out of the APK, hand it to a Hermes bytecode disassembler, and work from the decompiled JavaScript. In this case the bundle was readable enough that `grep` and a careful read beat any tooling.
