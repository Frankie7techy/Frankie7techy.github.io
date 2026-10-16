---
title: "Fianchetto: A 2048-Bit Modulus, Undone by a 160-Bit Secret"
date: 2026-10-15
draft: false
description: "The public modulus is a healthy 2048 bits. The public exponent is 2045 bits, which is the tell: when e is nearly as large as N, the private exponent d must be tiny. Wiener's attack walks the continued fraction of e/N until the key falls out."
tags: ["CTF", "Cryptography", "RSA", "Wiener Attack", "Continued Fractions", "Python"]
categories: ["Crypto"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Crypto</span>
    <span class="dr-badge red">Medium</span>
    <span class="dr-badge cyan">200 pts</span>
    <span class="dr-badge ghost">r00t CTF · Fianchetto</span>
  </div>
  <div class="dr-title">FIANCHETTO</div>
  <p class="dr-sub">An RSA public key with a <strong>2048-bit</strong> modulus and a <strong>2045-bit</strong> exponent. That second number is the whole story: <code>e</code> has been pushed almost all the way up to <code>N</code>, which means the matching private exponent <code>d</code> is necessarily small. Wiener's attack does the rest.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">2048</span><span class="l">bit modulus</span></div>
  <div class="dr-stat"><span class="n red">2045</span><span class="l">bit exponent</span></div>
  <div class="dr-stat"><span class="n cyan">160</span><span class="l">bit secret d</span></div>
  <div class="dr-stat"><span class="n">1</span><span class="l">convergent hit</span></div>
</div>

## The setup

The challenge hands over the usual RSA triple — modulus `N`, public exponent `e`, ciphertext `c` — and nothing else.

```json
{
  "N": 21628853238141112392066120644245035637898051301521204052519872151075354212443698775296090168658459312276352983699549274729155804235956629526312113416602639733429473907178534201345097956738939429821675635991804706536719193919299218725325426610479915745784150581786613187594190544043807937531855238571792755874655266611700399613886794830123768156910975745220764469350079208499568672814533678429759941695070917317557917187885501235988615040221677728711934446042777885017682530841992181918112024933992291183028539227111710747204983014217042929975351334353704016305501684756277651934831799015368242218199579694525917816719,
  "e": 3725470837699155909987625207037153662703837140688738513128863709032220178387659345919989529945025956137644475464351967605611793327937140837472370428628653822870924839498181949396738158371657317154475433483904587380509174760175047317765551184211444276125099988291254237454472313423839128237984472759831563492153797813054559232638671422015374554317712645554117517712544845924042726897774145978786047690779117712141604483362010906525122300505512839158332201760462607842667937645020436066720869513549852836815031204668824983050851301175224708340961578349445117670852078122821069992433947740448239085450560494245915708371,
  "c": 5201170649088591332605310462750685774395637632316021749389157151633601518544165491141167787223754634116301977400291282823120034768527229517623701470915194215470450464774937899890055808687869138315915543857543471214855245322202251357642156380898531759558452582091760960627191642137057690677925111725448594241531509652365334490289134292657675169881674671878705230072574509426409720881582146267593353707251990732547830032383737431776131744420483243903471758513317184875178603989719551828381719004971965279811950608661987162163280948214378914910926044409756731693670253674609082099830236030764876340817662797247475488143
}
```

`N` is a full 2048 bits. Nothing to attack there. But count the bits in `e`: **2045**. The public exponent is sitting almost exactly at the top of the modulus.

![The Fianchetto chain: an oversized e, a tiny d, and Wiener's continued fraction](/public/images/fianchetto/00_chain.svg)

## Why a huge e betrays a tiny d

RSA wants `e · d ≡ 1 (mod φ(N))`. If `e` is enormous but `φ(N) ≈ N` is only 2048 bits, then for the product `e · d` to wrap back around to a value congruent to 1, `d` has to be **small**. Concretely, the relation `e·d = 1 + k·φ(N)` means:

```
e / φ(N) ≈ k / d
```

So `k/d` is an unusually good rational approximation of `e/N`. And rational approximations of that quality are exactly what **continued fractions** produce. Wiener's theorem puts a number on it: if `d < ⅓ · N^(1/4)` — about 512 bits for this modulus — then `k/d` appears among the convergents of `e/N`.

Here `d` is 160 bits. The bound is not merely met, it is lapped.

## The attack

Take the continued fraction expansion of `e/N`, walk its convergents `k/d`, and for each candidate test whether it is the real thing. A candidate is correct when `(e·d − 1)` divides cleanly by `k` to give a `φ`, and `φ` is consistent with `N` factoring into two integers.

```python
#!/usr/bin/env python3
import json, math

data = json.load(open("fianchetto_challenge.json"))
N, e, c = data["N"], data["e"], data["c"]

def contfrac(a, b):
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    return cf

def convergents(cf):
    n0, n1, d0, d1 = 0, 1, 1, 0
    for q in cf:
        n0, n1 = n1, q * n1 + n0
        d0, d1 = d1, q * d1 + d0
        yield n1, d1

for k, d in convergents(contfrac(e, N)):
    if k == 0 or d == 0:
        continue
    if (e * d - 1) % k != 0:          # phi must come out whole
        continue
    phi = (e * d - 1) // k
    s = N - phi + 1                    # p + q
    disc = s * s - 4 * N               # (p - q)^2
    if disc < 0:
        continue
    t = math.isqrt(disc)
    if t * t != disc:                  # not a perfect square -> not our pair
        continue
    p, q = (s + t) // 2, (s - t) // 2
    if p * q != N:
        continue
    m = pow(c, d, N)
    print("[+] d =", d)
    print("[+] p =", p)
    print("[+] q =", q)
    print("[+] flag:", m.to_bytes((m.bit_length() + 7) // 8, "big").decode())
    break
```

The loop exits on the first convergent that factors `N`. In this challenge that is essentially immediate — the winning `k/d` is early in the list.

<div class="dr-callout">
  <span class="t">Two guards do the work</span>
  <p>The congruent-1 check on <code>(e·d − 1) % k</code> throws out almost every convergent in O(1). The perfect-square check on the discriminant is the final filter. Together they turn "search an unbounded space" into "try a handful of fractions".</p>
</div>

## Running it

```bash
$ python3 solve.py
[+] found private exponent d = 772939447021895568703677949971438238727760492091
[+] p = 152347720032201232945300405703561050373510602137391821460463322411477450457323133518021964488189112705269670836847439929735697994290299910071778197743822439942495547365516018651701268861845785401535399298863239860624544471599552338532172130635194857543491450501239509211376735102397376039058423316462855265797
[+] q = 141970311295564471373256099041321436038176149146828187122507629494704558750806585715612433009909397244692587841863354135252384743993614555662281573837119871771240682290531374239143881702983313989806964819693265064784481326842670806267968497407603981982868149923000216613728308819175018537137426921788953546627
[+] plaintext (bytes): b'r00t{w13n3rs_4tt4ck_br34ks_sm4ll_d}'
[+] plaintext (text) : r00t{w13n3rs_4tt4ck_br34ks_sm4ll_d}
```

A 2048-bit key broken by 160-bit `d` and two perfect-square checks.

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{w13n3rs_4tt4ck_br34ks_sm4ll_d}</code>
</div>

## Takeaway

Fianchetto is a lesson in key **balance**. A big modulus is worthless if its exponent pair is lopsided.

- **Read the exponent, not just the modulus.** `e ≈ N` is the loudest possible hint. A healthy `e` is 65537; anything astronomically larger deserves suspicion.
- **Wiener is cheap to try.** If you suspect a small `d`, running continued fractions on `e/N` costs milliseconds and either finds the key or rules the idea out.
- **Do not roll small `d` "for speed".** Modern libraries reject or warn on dangerously small private exponents. This class of implementation bug is decades old and still shows up.
