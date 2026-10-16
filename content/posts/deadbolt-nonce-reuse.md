---
title: "DeadBolt: Two Signatures, One Nonce, One Dead Key"
date: 2026-10-14
draft: false
description: "A release-signing service on secp256k1 published two ECDSA signatures that share the same r. That one repeated value is the whole challenge: the nonce falls out of it, and the nonce hands you the private key. No lattice, no brute force, just modular arithmetic."
tags: ["CTF", "Cryptography", "ECDSA", "Nonce Reuse", "secp256k1", "Python"]
categories: ["Crypto"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Crypto</span>
    <span class="dr-badge red">Medium</span>
    <span class="dr-badge cyan">200 pts</span>
    <span class="dr-badge ghost">r00t CTF · DeadBolt</span>
  </div>
  <div class="dr-title">DEADBOLT</div>
  <p class="dr-sub">A release-signing service signs its build manifests with <strong>secp256k1</strong>. It handed us the public key and two signatures over two different releases — and both of them share the same <strong>r</strong>. That single coincidence collapses the whole scheme.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">2</span><span class="l">signatures</span></div>
  <div class="dr-stat"><span class="n red">1</span><span class="l">repeated nonce</span></div>
  <div class="dr-stat"><span class="n cyan">1</span><span class="l">key recovered</span></div>
  <div class="dr-stat"><span class="n">0</span><span class="l">brute force</span></div>
</div>

## The setup

`deadbolt.json` is short. It names the curve, gives us a public key, and hands over two signatures over two different messages:

```json
{
  "curve": "secp256k1",
  "public_key": {
    "x": 112663615484051465733958221339258257849063613947361413621230845351083321471652,
    "y": 20707203924145238549824648964187237183894019142576647064731492330797666162633
  },
  "signatures": [
    {
      "message": "RELEASE-MANIFEST-2026-10-01: build 4471, approved for production rollout",
      "r": 81068046878512155195417425815628850251053346547441462714808971338416069090423,
      "s": 3840508737756347497406687710396332359740879825496539163063209443880034111304
    },
    {
      "message": "RELEASE-MANIFEST-2026-10-02: build 4472, hotfix for build 4471, approved",
      "r": 81068046878512155195417425815628850251053346547441462714808971338416069090423,
      "s": 113503929155425957381462365769873416436477654667784827574471421629337517804939
    }
  ]
}
```

Read those two `r` values again. They are **identical**, digit for digit.

![The DeadBolt chain: two signatures, one repeated r, one recovered private key](/public/images/deadbolt/00_chain.svg)

<div class="dr-callout danger">
  <span class="t">The whole challenge</span>
  <p><strong>r is a function of the nonce, not of the message.</strong> In ECDSA, <code>r = (k·G).x mod n</code>. Two signatures with the same <code>r</code> were signed with the same <code>k</code>. Once you know that, the private key is two lines of arithmetic away.</p>
</div>

## Why a repeated r is fatal

ECDSA signing for a message hash `z` with private key `d` and nonce `k` is:

```
r = (k · G).x  mod n
s = k⁻¹ · (z + r · d)  mod n
```

`r` depends only on `k` and the generator `G` — the message never touches it. So if two signatures share an `r`, they share a `k`:

```
s₁ = k⁻¹ (z₁ + r·d)
s₂ = k⁻¹ (z₂ + r·d)
```

Subtract them. The `r·d` term cancels:

```
s₁ − s₂ = k⁻¹ (z₁ − z₂)
```

Solve for the nonce:

```
k = (z₁ − z₂) · (s₁ − s₂)⁻¹   mod n
```

Now put `k` back into either signature and solve for `d`:

```
d = (s₁ · k − z₁) · r⁻¹        mod n
```

That is it. Every quantity on the right is public except nothing. `z` is just `SHA-256(message)` read as a big-endian integer, and `n` is the secp256k1 group order.

<div class="dr-callout warn">
  <span class="t">The one rule of deterministic-ish signing</span>
  <p>This is precisely why RFC 6979 exists. A nonce must be <strong>unique per message</strong>. Reusing it — or drawing it from a weak random source — leaks the key even if everything else is done perfectly.</p>
</div>

## The solver

The order is the secp256k1 curve order, and the hash is plain SHA-256. Everything else is one modular inverse.

```python
#!/usr/bin/env python3
"""Recover an ECDSA private key from two signatures made with the same nonce k."""
import hashlib, json

data = json.load(open("Deadbolt/deadbolt.json"))

# secp256k1 group order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def z_of(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")

sigs = data["signatures"]
(z1, r, s1) = (z_of(sigs[0]["message"].encode()), sigs[0]["r"], sigs[0]["s"])
(z2, _, s2) = (z_of(sigs[1]["message"].encode()), sigs[1]["r"], sigs[1]["s"])

assert r == sigs[1]["r"], "the whole attack depends on r repeating"

# k = (z1 - z2) / (s1 - s2)  mod n
k = (z1 - z2) * pow(s1 - s2, -1, n) % n

# d = (s1 * k - z1) / r  mod n
d = (s1 * k - z1) * pow(r, -1, n) % n

print("k =", hex(k))
print("d =", hex(d))
```

Two modular inverses and we are done.

```
k = 0x7576cf13562f78cfbaba95c33d489a77e6f7f22d9370c7220bbb5408501ee1b5
d = 0x5df81c47561875700a49e3010aeccb422b220c2c3d516b580a3d6ba2af4093a
```

<div class="dr-callout">
  <span class="t">Sanity check</span>
  <p>We never had to touch the public key to <em>find</em> <code>d</code>. It is only useful afterwards, to confirm we did not fat-finger the arithmetic — which is exactly what the supplied <code>checker.py</code> does.</p>
</div>

## Handing it to the checker

The challenge ships a `checker.py` that recomputes the public key from a candidate `d` and only prints the flag if it matches:

```bash
$ python3 Deadbolt/checker.py 2656466760151853485113498278724311908926037894305005865198209398276174907706
Key verified.
r00t{n0nc3_reu5e_l34k5_th3_pr1v4t3_k3y}
```

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{n0nc3_reu5e_l34k5_th3_pr1v4t3_k3y}</code>
</div>

## Takeaway

DeadBolt is a two-line maths challenge wearing a "modern crypto" costume. The tell is structural, not statistical: you do not need to break secp256k1, you only need to notice that one field is byte-identical across two otherwise unrelated signatures.

- **Spot the invariant.** Two signatures, one `r`. That is the entire vulnerability, and it is visible without any tooling.
- **Subtract, do not factor.** Nonce reuse is a linear problem. No lattices, no Coppersmith, no brute force.
- **The fix is old and boring.** RFC 6979 (deterministic nonces) or a properly seeded CSPRNG for `k`. Signing libraries get this right; hand-rolled signers historically do not.
