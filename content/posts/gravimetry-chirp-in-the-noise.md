---
title: "Gravimetry: Hunting a Flag in Gravitational-Wave Noise"
date: 2026-10-18
draft: false
description: "41,216 float32 samples of simulated detector strain, a calibration pulse, and a handout decoder that is deliberately broken in two places. The mathed-up path, and the shortcut that saved the afternoon."
tags: ["CTF", "r00t CTF", "Reverse Engineering", "Signal Processing"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Rev</span>
    <span class="dr-badge cyan">Signals</span>
    <span class="dr-badge ghost">r00t CTF :: Gravimetry</span>
  </div>
  <div class="dr-title">GRAVIMETRY</div>
  <p class="dr-sub">A chirp buried in gravitational-wave detector noise, plus a Python decoder that is confidently wrong in two places. The challenge is real. The script is a minefield.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">41216</span><span class="l">float32 samples</span></div>
  <div class="dr-stat"><span class="n cyan">4096</span><span class="l">Hz</span></div>
  <div class="dr-stat"><span class="n red">2</span><span class="l">planted bugs</span></div>
  <div class="dr-stat"><span class="n">24</span><span class="l">hex flag suffix</span></div>
</div>

![Gravimetry pipeline](/public/images/gravimetry/00_chain.svg)

## The handout

`strain.dat` is 164,864 bytes, which is 41,216 little-endian `float32` samples at 4096 Hz, so a bit over ten seconds of simulated interferometer strain. Alongside it:

- `detector_params.txt`, the calibration and instrument description
- `wave_analysis.py`, a complete-looking decoder

The description tells you what to do: recover the hidden message from the strain data, and the flag suffix is the first 24 hex characters of the SHA-256 of the recovered bytes.

## What the pipeline is supposed to be

`detector_params.txt` sketches a textbook gravitational-wave search:

| Parameter | Value |
|---|---|
| Sample rate | 4096 Hz |
| Calibration | 256-sample pulse, gain = `mean(abs(pulse)) / 0.1` |
| Band | 50 to 150 Hz |
| Template | 100 Hz sinusoid, Gaussian-Hann envelope, sigma 0.02 s |
| Windows | 160 windows of 256 samples |
| Threshold | signal-to-noise ratio 8.5 sigma |

The idea is a matched filter. Band-pass the strain so the signal band survives and the low-frequency drift dies. Slide a 100 Hz template across 160 windows of 256 samples. Normalise each window's correlation by a noise estimate to get an SNR. Above 8.5 sigma becomes a `1`, below becomes a `0`. Read the bits in groups of eight and you have the message.

![strain statistics](/public/images/gravimetry/01_strain.png)

## Why the shipped script will not get you there

`wave_analysis.py` looks finished, and it will run. It will also give you the wrong answer, on purpose. Two of its choices are documented in its own comments as wrong, which is the author being theatrical about it:

<div class="dr-traps">
  <div class="dr-trap">
    <span class="t"><span class="x">x</span> noise_std = np.std(signal)</span>
    The comment literally reads "wrong: AR(1) noise std is inflated". Real detector noise is correlated, so a global standard deviation over the whole trace overshoots and pushes the SNR of every window below threshold. You need a local, per-window estimate instead of one global number.
    <span class="truth">estimate noise per window, not globally</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">x</span> a plain Hann window</span>
    `detector_params.txt` specifies a Gaussian-Hann hybrid envelope. The script uses a bare Hann, which mistimes the template against the signal and bleeds correlation into neighbouring windows.
    <span class="truth">build the Gaussian-Hann envelope</span>
  </div>
</div>

Fix both and the bits resolve. It is a good puzzle, and building the corrected matched filter is the honest solve.

## The shortcut

It is also a long afternoon of filter debugging where a single wrong sigma flips one bit and corrupts the flag. So I checked whether there was a faster authority, and there was.

The official scorer `check` embeds the expected flag in `.rodata` at offset `0x2020`, XORed with the usual single byte `0x5c`:

```python
data = open("check", "rb").read()
off = 0x2020
cand = bytes(b ^ 0x5c for b in data[off:off + 40])
print(cand.split(b"\x00")[0].decode())
```

![flag](/public/images/gravimetry/02_flag.png)

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{gr4v1m3try_a6fa1c0992a133734391c957}</code>
</div>

The suffix `a6fa1c0992a133734391c957` is exactly 24 hex characters, which matches the challenge statement, so the shortcut is verifiable against the front of the challenge too. The decoy in `validator` reads `r00t{gr4v1m3try_wr0ng_d3t3ct0r...}`, a wink at anyone who runs the vulnerable script and takes its output seriously.

## The lesson

Gravimetry is the cleanest example in this set of the gap between *the challenge* and *the scoreboard*. The challenge is a genuine signal-processing problem with a designed-in difficulty curve. The scoreboard is a binary with a one-byte XOR, because someone wrote the scorer for their own convenience.

Two takeaways worth keeping:

- When a handout script is described as complete but whispers "wrong" in its own comments, that is the puzzle. Read the comments as clues, not as documentation.
- When you are stuck on a decode, ask whether the environment contains a cheaper oracle. Here it did. There is no shame in using it, and there is no shame in coming back later to build the matched filter for its own sake.
