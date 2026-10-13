---
title: "Phantom Drop: A PowerShell Dropper Wearing a Windows Update Badge"
date: 2026-10-13
draft: false
description: "A 45-packet capture, 52 seconds long, that shows a Windows implant checking in, pulling a payload, staging it, and mailing credentials home. Almost all of it is plain HTTP, and the flag is sitting in the exfil report."
tags: ["CTF", "Forensics", "Network Forensics", "Malware Analysis", "PowerShell"]
categories: ["Forensics"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Forensics</span>
    <span class="dr-badge red">Network</span>
    <span class="dr-badge cyan">1 flag</span>
    <span class="dr-badge ghost">r00t CTF · Phantom Drop</span>
  </div>
  <div class="dr-title">PHANTOM DROP</div>
  <p class="dr-sub">A short packet capture from a workstation that made <strong>five requests it should not have made</strong>. One of them fetches an executable dressed up as a Windows Update cabinet. One of them posts credentials to a domain that is not a telemetry service. The whole intrusion fits in under a minute, and it never bothered to encrypt.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n cyan">45</span><span class="l">Packets total</span></div>
  <div class="dr-stat"><span class="n">52<small>s</small></span><span class="l">Capture window</span></div>
  <div class="dr-stat"><span class="n red">3</span><span class="l">Malicious domains</span></div>
  <div class="dr-stat"><span class="n">1</span><span class="l">Flag recovered</span></div>
</div>

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{p0w3rsh3ll_dr0pp3r_appdAta_3xf1l}</code>
</div>

## TL;DR

The capture is small enough to read end to end, which is the whole gift here. The story it tells:

1. The host (`WKSTN-09`, user `b.omondi`, domain `P3RFCORP`) pulls a file from `windowsupdate.com`. It comes back with an `MZ` header, so it is an executable pretending to be a cabinet.
2. It fetches `/stage1/loader.ps1` from `updates.cdn-delivery.net`, a hex encoded, XOR obfuscated PowerShell loader.
3. It beacons to `api.cloudmetrics-push.com` with host, user, OS and a campaign id, and gets told to fetch a payload.
4. It fetches the payload, a base64 ZIP.
5. It posts an exfil report to `telemetry.winupdate-sync.io` whose body is the same ZIP, now containing `credentials.txt` and `system_info.txt`.

Decode the report body and the flag falls straight out.

![Phantom Drop in five requests: a fake update, a loader, a beacon, a payload, and an exfil report](/public/images/phantom-drop/00_timeline.svg)

## Step 0: Read the Capture Before You Tool It

The archive holds one file, `capture.pcap`. Before reaching for anything, I ask it how big it is:

![The capture is 45 packets over 52 seconds, mostly DNS and plain HTTP](/public/images/phantom-drop/01_pcap.png)

Forty five packets. Eighteen DNS, twenty seven TCP, ten HTTP frames. A capture this small means I do not need a strategy, I need to look at every request. The protocol hierarchy also says something useful out loud: there is no TLS. Every byte here is readable.

<div class="dr-callout">
  <span class="t">First observation</span>
  <p>Eighteen DNS queries against ten HTTP requests, on a workstation, in under a minute. That ratio is normal for a chatty Windows box. What is not normal is <em>which</em> names appear.</p>
</div>

## Step 1: Separate the Noise From the Names

A workstation talks to a lot of legitimate services, and this one does too. `www.google.com`, `login.microsoftonline.com`, `fonts.googleapis.com`, `ocsp.digicert.com`. All expected, all boring. Then three names stand out because they are impersonating infrastructure:

- `updates.cdn-delivery.net` serves the stage one loader.
- `api.cloudmetrics-push.com` runs the beacon and the payload.
- `telemetry.winupdate-sync.io` receives the exfil report.

They are built to pass a glance. "cdn delivery", "cloud metrics", "telemetry". No one reading a firewall log at 2am stops on those. But they are the only three names in the capture that are not a well known provider, and all three are on the same side of the conversation: the workstation is talking to them, not the reverse.

## Step 2: Carve the HTTP Objects

With plain HTTP, the fastest path from capture to artifacts is object extraction:

![tshark exports five HTTP objects, including a cab file with an MZ header](/public/images/phantom-drop/02_objects.png)

Five objects, and each one is a piece of the chain:

<div class="dr-verdict">
  <div class="half ghosts">
    <span class="big">wuident.cab</span>
    Pulled from a real-looking Windows Update path, but its first bytes are <code>4d 5a 90</code>. That is a PE executable, not a cabinet.
  </div>
  <div class="half auth">
    <span class="big">loader.ps1</span>
    4170 bytes of ASCII hex that decodes to a XOR obfuscated PowerShell stage. The dropper itself.
  </div>
</div>

The `.cab` detail is the nicest part of the challenge. It borrows one of the most trusted filenames on a Windows machine, `wuident.cab` under the genuine `windowsupdate.com` host, and swaps the contents for an executable. Defender heuristics see a signed looking update path; a human sees "cab" and moves on.

The loader is a two layer wrap. First hex, to make it look like a blob, then a repeating key XOR to keep the strings away from `strings`. A printability search over candidate key lengths cracks it in seconds once you spot the pattern, because the plaintext is still PowerShell and PowerShell has a very specific vocabulary.

## Step 3: The Beacon Introduces the Host

The third request is the check-in, and it volunteers a lot of context about the machine it has just compromised:

![The beacon is base64 JSON that names the host, the user, and the operating system](/public/images/phantom-drop/03_beacon.png)

Decoded, it is a tidy little census:

```
cid    d8f3c1a0-4e7b-4f2a-8c9d-2b1f0e3a5d7c
host   WKSTN-09
user   b.omondi
os     Windows 10 Pro 22H2
ts     2026-11-10T09:01:44Z
task   ready
```

The server's reply to that beacon is a single instruction: `fetch_payload`. The implant obeys. A moment later it asks `api.cloudmetrics-push.com` for the payload and gets back 342 bytes of base64, a ZIP prefix delivered as a partial response. That is the second stage landing, and the name of the flag, `appdAta_3xf1l`, tells you where it is going: a dead drop in `%AppData%`.

## Step 3b: The Report That Carries the Flag

The last request is the exfil. The implant posts a form to `telemetry.winupdate-sync.io/report` with five fields: `machine`, `user`, `domain`, `ts`, and a `data` blob. That `data` field is the same base64 ZIP, now complete:

![The exfil report decodes to a zip containing credentials and host details](/public/images/phantom-drop/04_exfil.png)

Decode it and the ZIP opens cleanly:

```
exfil blob len: 371   magic: PK 03 04
zip entries: credentials.txt, system_info.txt
```

`system_info.txt` is just confirmation: host `WKSTN-09`, Windows 10 Pro 22H2, user `b.omondi`, domain `P3RFCORP`. `credentials.txt` is the payload the attacker actually cared about, an internal credential export:

```
AdminUser:   p3rf_svc_backup
AdminPass:   S3cur3Backup!2026
DBConnStr:   Server=DBSRV01;Database=HRCore;User=sa;Password=H!R_D@T4_2026
```

And at the bottom, the CTF flag, which the challenge author was kind enough to append:

<div class="dr-callout ok">
  <span class="t">Recovered</span>
  <p><code>r00t{p0w3rsh3ll_dr0pp3r_appdAta_3xf1l}</code></p>
</div>

## Why It Worked, and What Would Have Caught It

The intrusion never needed encryption or a zero day. It needed a filename people trust and a channel people rarely inspect. Two detections cover most of it:

<div class="dr-traps">
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> Trusting the filename over the bytes</span>
    <code>wuident.cab</code> returned an executable. Checking the magic bytes of anything that lands in a temp or update path catches this instantly.
    <span class="truth">PE where a CAB belongs</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> PowerShell reaching the internet</span>
    A loader pulled over HTTP and executed by PowerShell is the loudest signal in the capture. Constrained Language Mode and script block logging both see it.
    <span class="truth">stage 1 never runs</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> Outbound POSTs with a base64 body</span>
    The exfil is a single form POST to a domain with no business reason to exist. Egress filtering plus content inspection breaks the last hop.
    <span class="truth">credentials stay on the host</span>
  </div>
</div>

<div class="dr-callout warn">
  <span class="t">Takeaway</span>
  <p>Phantom Drop is a reminder that the quietest intrusions are the ones that look like the machine doing its job. "Checking Windows Update" is not suspicious. It is the absence of a second look that <em>is</em> the vulnerability.</p>
</div>

## Flag

<div class="dr-flag">
  <span class="l">Phantom Drop</span>
  <code>r00t{p0w3rsh3ll_dr0pp3r_appdAta_3xf1l}</code>
</div>
