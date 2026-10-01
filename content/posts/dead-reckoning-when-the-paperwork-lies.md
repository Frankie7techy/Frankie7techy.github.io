---
title: "Dead Reckoning — When the Paperwork Lies, Trust the Physics"
date: 2026-10-01
draft: false
description: "A corrupted flight data recorder log, 13 ghost entries, and four different pieces of paperwork all trying to send me to the wrong answer. Reconstructing a Cessna's true flight path with nothing but dead-reckoning physics."
tags: ["CTF", "AfricaHackon", "Forensics", "Binary Analysis", "Dead Reckoning"]
categories: ["Forensics"]
authors: ["z3ro"]
---

## Challenge Overview

| Field | Value |
|---|---|
| **Platform** | AfricaHackon |
| **Challenge** | Dead Reckoning |
| **Author** | Dr Programmer |
| **Category** | Forensics |
| **Difficulty** | Hard |
| **Points** | 400 |
| **Given** | `fdr.bin` (1,158 bytes), `fdr-spec.txt`, `aircraft-manual.txt`, `validator`, `check` |

> *"A corrupted flight data recorder log from a SkyTrack-7 avionics unit contains 39 entries mixed with injected 'ghost' entries. The aircraft's true flight path must be reconstructed using dead-reckoning physics. Ghost entries are detectable because they violate aerodynamic constraints."*

**Flag:** `r00t{d34d_r3ck0n_2bb5989ca909476c23e75ba6ad05c64b}`

---

## TL;DR

A Cessna 172S flew Nairobi Wilson → Mombasa. Its flight data recorder caught 39 fixes — but a firmware fault (Advisory SA-019, a story the spec *really* wants you to believe) injected "ghost" entries with plausible timestamps and impossible positions.

The challenge hands you **four different ways to find the ghosts. All four are lies.** The only thing that tells the truth is Newton.

**The five moves:**
1. Parse the binary (26-byte header, 28-byte entries, big-endian)
2. Notice every "helpful" filter field is compromised
3. Chain dead-reckoning: predict each fix from the **last authentic** fix
4. Catch 13 ghosts — including one that *almost* passes
5. Dodge the decoy validator and the planted fake, feed the real scorer

---

## Step 0 — Reading the Paperwork (and Smelling a Rat)

![Extracting the challenge files and the buried hints](/public/images/dead-reckoning/01_challenge_files.png)

Five files. A spec, a manual, a binary, and two ELF scorers. So far so normal.

But the spec has an interesting personality. Section 7 — *"ANALYST SHORTCUT"* — warmly recommends:

> *"For rapid triage, filter by INSTR_ERROR == 0.0 ... then apply GPS_CORRECTED=1 for highest confidence. This two-step filter isolates authentic entries before full physics validation."*

And a "SkyTrack Advisory SA-022" says the same thing again, just in case you didn't feel *guided* enough. Section 5 then casually admits the checksum field (CSUM4) is **valid for corrupted entries** — the corruption happens *after* checksum computation — so that filter is dead on arrival too.

When a forensic spec contains two advisories, a shortcut, and a reference solver that all agree with each other, my suspicion gland starts tingling. Real documentation doesn't *sell* you a method. It gives you physics constants and gets out of the way.

And the manual? That part is gold, because it's honest:

- Earth model: **spherical, R = 6371.0 km**
- Standard log interval: **300 seconds, ±30 s per entry**
- DR error over a 5-minute cruise segment: **typically < 0.4 km**
- An authentic fix predicts the next authentic fix with error **< 1.0 km**
- Deviations beyond **~1.5 km** are suspect

That's everything needed to test every entry against reality. The manual is the toolkit; the spec is the trap.

---

## Step 1 — Parsing the Binary

The format is friendly: 26-byte header, then N × 28-byte entries, big-endian, then a trailer. Each entry carries timestamp, lat/lon (×10⁶), altitude, heading ×10, speed, FLAGS, and — new in "Spec v4.0" — an 8-byte float64 `INSTR_ERROR` field at offset 20.

```python
t, la, lo, alt, h10, spd, fl = struct.unpack('>iiiHHHH', data[off:off+20])
ie, = struct.unpack('>d', data[off+20:off+28])
```

Header says: aircraft `SKTK7`, base epoch 1741000000, **39 entries**. Parsing gives a clean table:

![Parsing fdr.bin — header fields and the first entries](/public/images/dead-reckoning/02_fdr_parse.png)

Look at entries 3 and 6. Entry 3 has the **same timestamp as entry 2** (dt = 0) — a duplicated fix the aircraft could not have produced while moving 16 km every five minutes. Entry 6 is 77.6 km off the predicted track, heading northwest while the plane flies southeast toward Mombasa.

Ghosts, obviously. But now the interesting part — **watch the fields lie.**

---

## Step 2 — Every Helpful Field Is a Liar

Here's the evidence table from the ghosts I caught:

| Trap | Reality |
|---|---|
| `INSTR_ERROR == 0.0` filter | **Five ghosts pass it** (#3, #10, #16, #23, #30 all have `ie = 0.0`). Meanwhile authentic entry #19 has `ie = 284.0` — the filter would drop a *real* fix and keep fake ones. |
| `GPS_CORRECTED = 1` filter | **Six ghosts have the bit set** (#4, #10, #12, #16, #26, #32). The "authoritative" signal marks fakes. |
| `CSUM4` checksum | Fails on **authentic** entries too. The spec even admits why: the fault corrupts entries *after* checksumming. Pure noise. |
| Trailer `NOTE` | Contains a planted fake: `r00t{FAKE_DR_GPS_C0RRECT3D_D3C0Y}` — it literally self-identifies, but only after you've already wasted an evening. |

The spec's "shortcut" is the exact wrong answer, dressed in helpful clothing. This is the best trap design I've seen in a while: nothing is *broken* — the misdirection is all in what the paperwork *emphasizes*.

---

## Step 3 — The Physics Never Lies

So forget the fields. The only trustworthy instrument is **dead reckoning**: if the aircraft was at position P with heading θ and speed v, then Δt seconds later it *must* be within a predictable circle of where P says it should be. No field can fake that, because physics doesn't have a FLAGS register.

The manual gives the exact formula (spherical Earth):

```
d  = v × 1.852 × Δt / 3600                    [km]
φ₂ = arcsin( sin(φ₁)·cos(d/R) + cos(φ₁)·sin(d/R)·cos(θ) )
λ₂ = λ₁ + atan2( sin(θ)·sin(d/R)·cos(φ₁),  cos(d/R) − sin(φ₁)·sin(φ₂) )
```

The one rule that matters: **chain from the last AUTHENTIC fix, never from the previous entry.** A ghost must never pollute the reference track — otherwise one injected fix drags your predictions off and everything downstream looks suspect.

![The dead-reckoning chain catching ghosts](/public/images/dead-reckoning/03_dr_physics.png)

The result is beautiful:

- **Every authentic fix** lands within **0.0–0.33 km** of its prediction — inside the manual's < 0.4 km DR error budget — and every single one is **exactly 300 s** after the previous authentic fix.
- **Every ghost** is 2.4–148.6 km off-path, with a duplicated timestamp or an off-interval 180/240 s gap.

Zero gray area. 26 authentic, 13 ghosts:

```
ghost indices: [3, 4, 6, 10, 11, 12, 16, 17, 19, 23, 26, 30, 32]
```

---

## Step 4 — Entry 19, the Ghost That Studied for the Test

This is the trap for people who survive trap #1, and it deserves its own section.

Entry 19 is *nearly* perfect. It's only **1.03 km** off the predicted position — comfortably inside the manual's "~1.5 km = suspect" line. Its timestamp is plausible. It even sits geometrically between fixes #18 and #20, right on the flight path to Mombasa. My first solver **kept it.**

But three things give it away:

1. **It's 3× the DR error budget.** Real fixes deviate 0.0–0.33 km from prediction. Entry 19's 1.03 km isn't sensor noise — it's injection residue.
2. **Its interval is wrong.** Authentic fixes are exactly 300 s apart. Entry 19 sits 240 s after #18 — outside the ±30 s tolerance — and would force #20 into a nonsensical 60 s gap.
3. **The chain doesn't need it.** Predicting #20 directly from #18: error **0.14 km**. The flight path is continuous without entry 19 — it's a splinter, not a step.

And notice the bait: entry 19 carries `ie = 284.0`, so the spec's SA-022 shortcut — "filter on INSTR_ERROR == 0.0 as a primary triage step" — would have you **delete this ghost and lose the one entry whose `ie` field is a lie in the other direction.** The challenge's misdirection field is designed to be *almost* right about everything. Respect.

---

## Step 5 — The Decoy Gauntlet

![The decoy validator blessing a flag the real scorer rejects](/public/images/dead-reckoning/04_decoy_gauntlet.png)

With ghosts filtered, two scorers remain. `validator` greets a candidate flag with a warm **VALID** and tells you to "submit to ./check for official scoring."

So I did. `check` said **WRONG.**

The validator is a decoy — it blesses exactly one string, and that string is not the answer. Both binaries are tiny ELF files that read a line from stdin, XOR-decode an embedded blob (validator's key: `de c0 ad be`; check's: `00 45 26 47`), and compare. Two "validators," two different truths, and the challenge description *warned* me one of them accepts incorrect answers. The trailer's `FAKE_DR_GPS_C0RRECT3D_D3C0Y` fake rounds out the gauntlet.

Three planted wrong answers, one real scorer, and a manual telling the truth the whole time.

---

## Step 6 — The Flag

![check confirming the real flag](/public/images/dead-reckoning/05_flag_revealed.png)

```
r00t{d34d_r3ck0n_2bb5989ca909476c23e75ba6ad05c64b}
```

**CORRECT.** 400 points, first blood of the challenge went to someone else — but the flight path made it home in one piece, and that's what matters.

---

## Why You Should Care at 2 AM (Defender Notes)

Dead reckoning as an integrity check isn't just a CTF trick — it's how real GPS-spoofing detection works:

1. **Telemetry must be *internally consistent*, not merely *labeled authoritative*.** Every spoofed ADS-B track ever caught failed exactly this way: plausible fields, impossible physics.
2. **Chain from trusted state, never from the previous sample.** One poisoned fix that contaminates your reference track makes every downstream check worthless. This is true for FDR logs, for sensor streams, and for anything else that arrives "with plausible timestamps."
3. **The best traps aren't broken — they're documented.** The dangerous part of this challenge wasn't the corruption; it was a spec that *recommended* the wrong filter. In real incidents, that's a vendor advisory that says "filter on field X" when field X is compromised. Trust constraints, not recommendations.
4. **Verify the verifier.** Two scorers with two different truths is a supply-chain story in miniature: if you don't know where your validator's truth comes from, you're just running someone else's bug.

One deviation of 1.03 km is a rounding error. *One* deviation of 1.03 km that appears exactly when every field in the record swears nothing is wrong — that's a ghost with excellent study habits.

---

## The Full Solver

```python
#!/usr/bin/env python3
"""Dead Reckoning (SkyTrack-7 FDR) — ghost-entry filter via chain dead reckoning."""

import struct
import math

R = 6371.0          # spherical Earth radius (km) — manual §4.4
HEADER_SIZE = 26
ENTRY_SIZE = 28

def parse_fdr(path):
    with open(path, 'rb') as f:
        data = f.read()
    ver, = struct.unpack('>H', data[4:6])
    aircraft = data[6:14]
    base, = struct.unpack('>q', data[14:22])
    n, = struct.unpack('>I', data[22:26])
    print(f"magic {data[:4].hex()}  ver {ver}  id {aircraft}  base {base}  n {n}")
    entries = []
    for i in range(n):
        off = HEADER_SIZE + i * ENTRY_SIZE
        t, la, lo, alt, h10, spd, fl = struct.unpack('>iiiHHHH', data[off:off + 20])
        ie, = struct.unpack('>d', data[off + 20:off + 28])
        entries.append(dict(i=i, t=t, lat=la / 1e6, lon=lo / 1e6, alt=alt,
                            hdg=h10 / 10.0, spd=spd, gps=bool(fl & 1), ie=ie))
    return entries

def dr_predict(e0, dt):
    """Predict position after dt seconds flying heading/speed of fix e0 (manual §4.4)."""
    d = e0['spd'] * 1.852 * dt / 3600.0
    p1, l1 = math.radians(e0['lat']), math.radians(e0['lon'])
    th = math.radians(e0['hdg'])
    p2 = math.asin(math.sin(p1) * math.cos(d / R) + math.cos(p1) * math.sin(d / R) * math.cos(th))
    l2 = l1 + math.atan2(math.sin(th) * math.sin(d / R) * math.cos(p1),
                         math.cos(d / R) - math.sin(p1) * math.sin(p2))
    return math.degrees(p2), math.degrees(l2)

def dist_km(lat1, lon1, lat2, lon2):
    """Great-circle distance (spherical Earth, R = 6371 km)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))

def main():
    entries = parse_fdr('fdr.bin')
    authentic = [entries[0]]          # chain from the LAST authentic fix
    ghosts = []
    for e in entries[1:]:
        prev = authentic[-1]
        dt = e['t'] - prev['t']
        plat, plon = dr_predict(prev, dt)
        dev = dist_km(plat, plon, e['lat'], e['lon'])
        interval_ok = 270 <= dt <= 330          # 300 s ± 30 s
        ok = (dev <= 1.0) and interval_ok       # physics envelope
        tag = 'AUTH' if ok else 'GHOST'
        print(f"{e['i']:3d} t={e['t']:6d} dt={dt:5d} pos=({e['lat']:9.4f},{e['lon']:9.4f}) "
              f"hdg={e['hdg']:6.1f} spd={e['spd']:3d} alt={e['alt']:5d} gps={int(e['gps'])} "
              f"ie={e['ie']:6.1f} dev={dev:8.2f}km {tag}")
        (authentic if ok else ghosts).append(e)
    print(f"\ntotal={len(entries)} authentic={len(authentic)} ghosts={len(ghosts)}")
    print("ghost indices:", [g['i'] for g in ghosts])

if __name__ == '__main__':
    main()
```

---

## Recap — Five Moves

| Step | Action |
|---|---|
| 1 | Parse the binary (26-byte header, 28-byte entries, big-endian) |
| 2 | Distrust every "helpful" field: `INSTR_ERROR`, `GPS_CORRECTED`, `CSUM4` all compromised |
| 3 | Chain dead-reckoning from the **last authentic** fix (R = 6371 km, 300 ± 30 s, < 1 km) |
| 4 | Catch 13 ghosts — including the 1.03 km near-perfect one |
| 5 | Reject the decoy validator and planted fake, feed the real scorer |

The paperwork lied four times. The physics went 4 for 4 the other way.

Trust the physics.

---

*Scripts: [dr_reckon.py](/public/files/dead-reckoning/dr_reckon.py) · [trailer.py](/public/files/dead-reckoning/trailer.py)*

*— Frank Ngaruiya (@z3r0bme)*
