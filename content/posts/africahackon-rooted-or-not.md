---
title: "AfricaHackon: Rooted or not? — Root Check? Bypassed Without Rooting Anything"
date: 2026-09-23
draft: false
description: "Android APK reversing — XOR key recovered, static analysis only. A vault app gates its debug panel behind a root check, but the flag is computed statically. No rooting, no emulator, no Frida needed."
tags: ["CTF", "AfricaHackon", "Mobile", "Reverse Engineering", "Android"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

## Challenge Overview

| Field | Value |
|---|---|
| **Platform** | AfricaHackon |
| **Challenge** | Rooted or not? |
| **Author** | LordSudo |
| **Category** | Mobile / Reverse Engineering |
| **Difficulty** | Easy |
| **Points** | 100 |
| **Operation** | "PERFECT ROOT" |

> A vault app exposes a debug panel — but the developers claim it's safe since it's gated behind a root check, and *"real users don't root their phones."*

**Files:** `Rooted or not.zip` → `vaultapp.apk`

---

## TL;DR

The app's entire security model is a single `File.exists("/system/bin/su")` check. The flag is computed **statically** via XOR with a deterministic key — no rooting, no emulator, no Frida needed. Pure static analysis wins again.

**The five moves:**
1. Unpack the APK (it's just a ZIP)
2. Strings recon on `classes.dex`
3. Disassemble the gate with androguard
4. Extract the ciphertext from `<clinit>`
5. Replay the XOR crypto offline in Python

---

## Step 1 — Unpack the APK

An APK is just a ZIP archive, so no special tooling is needed to look inside. The entire app is ~8.5 KB and `classes.dex` is only 1.6 KB — tiny enough to tear apart by hand.

![Extracting the APK](/public/images/rooted-or-not/step1_extract.png)

```bash
unzip "Rooted or not.zip"
unzip vaultapp.apk
```

---

## Step 2 — Strings Recon

Pulling printable strings out of `classes.dex` immediately reveals the attack surface:

- `/system/bin/su` — the classic root-detection path
- `unlockDebugFlag`, `deriveKey`, `ENCODED_FLAG`, `SEED` — the debug panel's "gate" and the crypto behind it

![Strings in classes.dex](/public/images/rooted-or-not/step2_strings.png)

---

## Step 3 — Disassemble the Gate

Using **androguard** (pure Python — runs fine on Windows where apktool/jadx wanted Java), the flow in `MainActivity.onCreate()` is clear:

```smali
invoke-static RootCheck;->isDeviceRooted()Z
if-eqz v0, +0xa            # rooted → print "Root detected - access denied"
invoke-static RootCheck;->unlockDebugFlag()Ljava/lang/String;   # not rooted → log flag
```

If the device is **not** rooted, the app just calls `unlockDebugFlag()` and prints the flag to logcat. So the "debug panel" is a red herring — **the flag is computed statically in code**.

![Root check gate in onCreate](/public/images/rooted-or-not/step3_disasm.png)

---

## Step 4 — The Whole "Protection"

`RootCheck.java` is the entire security model:

```smali
isDeviceRooted():
    new File("/system/bin/su").exists()

deriveKey(n):
    key[i] = (byte)(90 + 7*i)        # SEED = 90, step 7

unlockDebugFlag():
    flag[i] = ENCODED_FLAG[i] ^ key[i]
```

A single `File.exists()` check, and a deterministic XOR with a key anyone can regenerate. Nothing is fetched over the network, nothing depends on device state. The root check is security theater.

![RootCheck internals](/public/images/rooted-or-not/step4_rootcheck.png)

---

## Step 5 — Grab the Ciphertext

The static initializer (`<clinit>`) fills `ENCODED_FLAG` with a 40-byte payload via `fill-array-data`:

```
28 51 58 1b 0d 0e f0 bf e6 a8 c3 f8 9a db 88 af
b3 a2 e9 ac b9 8f 8d 8b 36 7a 63 24 6d 7a 58 5b
09 1e 2b 27 65 3e 0f 16
```

![ENCODED_FLAG payload](/public/images/rooted-or-not/step5_clinit.png)

---

## Step 6 — Replay the Crypto Offline

Since decryption is just `flag[i] = enc[i] ^ ((90 + 7*i) & 0xff)`, we can reproduce it in a Python one-liner — no rooted phone, no emulator, no Frida needed.

![Decoding the flag](/public/images/rooted-or-not/step6_flag.png)

```python
enc = bytes([0x28,0x51,0x58,0x1b,0x0d,0x0e,0xf0,0xbf,0xe6,0xa8,
             0xc3,0xf8,0x9a,0xdb,0x88,0xaf,0xb3,0xa2,0xe9,0xac,
             0xb9,0x8f,0x8d,0x8b,0x36,0x7a,0x63,0x24,0x6d,0x7a,
             0x58,0x5b,0x09,0x1e,0x2b,0x27,0x65,0x3e,0x0f,0x16])
key  = bytes(((90 + 7*i) & 0xff) for i in range(len(enc)))
print(bytes(a ^ b for a, b in zip(enc, key)).decode())
```

**Output:** 40 characters, clean printable ASCII.

---

## Flag

```
r00t{st4t1c_4n4lys1s_byp4ss3s_th3_ch3ck}
```

---

## Lessons Learned

- **A root check is not a vault.** Gating decryption keys behind runtime device state is meaningless when the ciphertext, key formula, and decrypt routine all ship in the APK.
- **Static analysis beats dynamic bypasses.** Before reaching for Frida/Magisk hide, check if the secret is computed deterministically — replaying it offline takes seconds.
- **Small DEX = fast wins.** Even without apktool/jadx, system Python (`zipfile` + `re`) gets you 80% of the way; androguard covers the rest with no Java dependency.

---

## The Full Script

```python
#!/usr/bin/env python3
"""Rooted or not? — offline flag decoder. No rooting required."""

import zipfile
import re

def extract_flag(apk_path):
    """Extract and decode the flag from the vault app APK."""
    with zipfile.ZipFile(apk_path) as zf:
        dex = zf.read('classes.dex')

    # Find the ENCODED_FLAG bytes in the DEX
    # Pattern: fill-array-data with 40 bytes
    pattern = re.compile(
        b'[\x28\x51\x58\x1b\x0d\x0e\xf0\xbf\xe6\xa8\xc3\xf8\x9a\xdb\x88\xaf'
        b'\xb3\xa2\xe9\xac\xb9\x8f\x8d\x8b\x36\x7a\x63\x24\x6d\x7a\x58\x5b'
        b'\x09\x1e\x2b\x27\x65\x3e\x0f\x16]'
    )

    # The XOR key: seed=90, step=7
    key = bytes(((90 + 7 * i) & 0xff) for i in range(40))

    # Find the ciphertext in the DEX
    match = pattern.search(dex)
    if match:
        enc = match.group()
        flag = bytes(a ^ b for a, b in zip(enc, key))
        return flag.decode('ascii', errors='ignore')
    return None

if __name__ == '__main__':
    flag = extract_flag('vaultapp.apk')
    print(f"Flag: {flag}")
```

---

*— Frank Ngaruiya (@z3r0bme)*
