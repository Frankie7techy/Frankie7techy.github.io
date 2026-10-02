---
title: "The Last Day — HR Said It Was Routine. The Logs Disagreed."
date: 2026-10-01
draft: false
description: "An insider threat hidden inside hand-crafted Windows event logs — records Event Viewer physically cannot show. The after-hours logon, the staged files, the 7-Zip exfil, and the flag buried in HR's own paperwork."
tags: ["CTF", "Digital Forensics", "Windows Event Logs", "Insider Threat", "Exfiltration"]
categories: ["Forensics"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Forensics</span>
    <span class="dr-badge red">Medium</span>
    <span class="dr-badge cyan">400 pts</span>
    <span class="dr-badge ghost">r00t CTF · k4p3re</span>
  </div>
  <div class="dr-title">THE LAST DAY</div>
  <p class="dr-sub">HR flagged it as routine: an employee's last day, standard offboarding. But between 02:47 and 03:07 one morning, an offboarded employee RDP'd back into <strong>WKSTN-14</strong>, staged sensitive files, read Finance contracts and saved browser passwords with a renamed binary, 7-Zip'd the lot, and uploaded it to a personal <strong>"vault"</strong> domain. Meanwhile HR's own paperwork quietly carried the flag.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n cyan">78</span><span class="l">Records in the files</span></div>
  <div class="dr-stat"><span class="n red">13</span><span class="l">Event Viewer could show</span></div>
  <div class="dr-stat"><span class="n">20<small> min</small></span><span class="l">Attack window</span></div>
  <div class="dr-stat"><span class="n">7<small>/7</small></span><span class="l">Solved — 400 pts</span></div>
</div>

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{th3_l4st_d4y_1ns1d3r_thr34t}</code>
</div>

## TL;DR

Two log exports land on your desk. You open them and Event Viewer shows **13 events**. The file sizes say 528 KB and 200 KB — and that math does not add up. The real story is in the records Event Viewer *physically cannot show*.

**The seven moves:**
1. Notice the file sizes don't match the event counts
2. Spot the after-hours RDP logon (Q1 + Q2)
3. Carve the EVTX files — 53 + 25 records, not 6 + 7
4. Find the Finance share access via a renamed `wsus.exe`
5. Catch the `7z.exe a -p client_exports_final.7z F:\Staging\*` command (Q3 + Q4)
6. Catch the exfil upload to `vault-personal-sync.io` (Q5 + Q6)
7. Read HR's account-disable records — one of them is not like the others (Q7)

![The attack timeline: logon to exfiltration in twenty minutes](/public/images/the-last-day/00_timeline.png)

## Step 0 — First Impressions: The Math Doesn't Add Up

Two log exports, and the numbers are already arguing with each other.

![Two log exports — 528 KB, but only six events](/public/images/the-last-day/01_first_look.png)

The Security log is **528 KB** but opens with **6 events**. The Sysmon log, 200 KB, shows **7**. Real EVTX files pack hundreds of records into 64 KB chunks — half a megabyte for thirteen events is not how event logs work.

<div class="dr-callout warn">
  <span class="t">Suspicion triggered</span>
  <p>Either someone shipped half a megabyte of empty padding, or <strong>something in these files is hidden</strong>. Hold that thought — and hold the one line in the visible six that already stands out: <code>TargetUserName: n.wanjiru</code>, <code>LogonType: 10</code>, at 2:47 in the morning.</p>
</div>

## Step 1 — The After-Hours Logon (Q1 + Q2)

The visible 4624 is the anchor of the whole story:

![Event 4624 — the after-hours RDP logon](/public/images/the-last-day/02_logon.png)

- **`n.wanjiru`** (P3RFCORP) — the employee who was offboarded *that same morning*
- **LogonType 10** — RemoteInteractive. That's RDP. Not a service, not a scheduled task — *a person, at a remote desktop*
- **`203.0.113.77`** — an external IP
- **02:47:12 AM** — well after anyone would normally have gone home

That's Q1 and Q2 banked. Everything that follows belongs to this session.

## Step 2 — The Carve: What Event Viewer Can't Show You

Here's the part that makes this challenge special.

Event Viewer and `Get-WinEvent` both go through the Windows Event Log API, which trusts the file's own index — its chunk headers. Check those first:

```text
"ElfChnk" magic:          not found
FileHeader.nextRecordId:  8        (we only saw 6 events)
```

No valid chunk headers. **Hand-crafted EVTX.** The API can only recover a fraction of what's physically in the file, because the index it relies on was stripped out.

So stop trusting the index and carve the records directly:

```python
import Evtx.Evtx as evtx
for record in evtx.Evtx('Security.evtx').records():
    print(record.xml())
```

![Get-WinEvent shows 6 + 7; python-evtx recovers 53 + 25](/public/images/the-last-day/03_hidden.png)

**Security: 53 records. Sysmon: 25.** Versus the 13 Event Viewer showed.

<div class="dr-callout danger">
  <span class="t">The pivot of the whole challenge</span>
  <p>EVTX records render through <strong>templates stored per-chunk</strong>, and some of these records reference templates that live in a <em>different chunk</em> than the one they sit in. python-evtx only looks in the record's own chunk — a few records still refuse to render until you pool every chunk's templates together and cross-reference. The hidden events are where the entire insider story lives.</p>
</div>

## Step 3 — The Folders No One Should Be Touching

Hidden among the recovered Security records: four **4663 file-access events**, all at 2:56 AM, all under `n.wanjiru`'s session:

![Event 4663 — Finance shares and browser credentials via wsus.exe](/public/images/the-last-day/04_shares.png)

- `C:\Shares\Finance\Q3_Client_Contracts.xlsx`
- `C:\Shares\Finance\Client_Master_List.xlsx`
- `...\Firefox\Profiles\kushu3sd.default\logins.json`
- `...\Chrome\User Data\Default\Login Data`

Finance contracts and saved browser passwords — *this* is what the description meant by "folders this employee had no reason to touch."

And the process doing the reading: `C:\Users\Defau1t\wsus.exe`. WSUS is a Windows service that lives in `C:\Windows\System32` — never in a user profile with a suspiciously familiar-looking name (`Defau1t`, with a one). **A renamed binary masquerading as Windows Update.** Classic T1036.

## Step 4 — Two Answers in One Command Line (Q3 + Q4)

An archiver has exactly one job: read files, write archives. But first, the process creation event at 3:03:45 AM in the carved Sysmon log hands us two answers gift-wrapped:

![Sysmon EID 1 — the 7z archive command](/public/images/the-last-day/05_7z.png)

```text
Image:        C:\Program Files\7-Zip\7z.exe
User:         P3RFCORP\n.wanjiru
CommandLine:  7z.exe a -p client_exports_final.7z F:\Staging\*
```

Read it like a sentence:

- **`F:\Staging`** — where the sensitive files were staged before archiving (Q3). Sysmon's file-create events confirm it: `F:\Staging\ClientExports_Raw.xlsx` appeared at 2:52 AM.
- **`client_exports_final.7z`** — the exact archive filename (Q4)
- **`-p`** — password-protected. The attacker locked the box before moving it.

## Step 5 — The Upload, Timestamped (Q5 + Q6)

An archiver does not make network connections. Ever. So when the carved Sysmon log shows `7z.exe` opening a TCP socket, you pay attention:

![Sysmon EID 3 — the exfiltration connection to vault-personal-sync.io](/public/images/the-last-day/06_exfil.png)

```text
Image:               C:\Program Files\7-Zip\7z.exe
Protocol:            tcp    Initiated: True
DestinationHostname: vault-personal-sync.io
DestinationPort:     443 (https)
TimeCreated:         2026-09-14 00:07:22 UTC   (03:07:22 AM local)
```

The archive leaves the machine *from the archiver itself*, to **`vault-personal-sync.io`** on 443 (Q5) — a domain pretending to be a personal cloud-sync service. The timestamp: **00:07:22 UTC** (Q6).

<div class="dr-callout warn">
  <span class="t">Timezone note — this one cost me a submission</span>
  <p>The log stores <code>00:07:22</code> UTC, which displays as <code>03:07:22 AM</code> on a UTC+3 machine. Which one does the platform want? After a few format guesses: the accepted answer was the <strong>full stored timestamp with the date</strong> — <code>r00t{2026-09-14 00:07:22}</code>. When a CTF asks "what time," try the exact timestamp as recorded in the log before anything cleverer.</p>
</div>

## Step 6 — The Paperwork Lies (Q7 + The Flag)

The final question points at HR: *"several account deactivations that same morning — standard offboarding, nothing unusual on the surface. But whoever handled the paperwork for this specific departure may have left something behind in the record."*

The carved Security log contains six **4725 (account disabled)** events from `HR-ADMIN01` — same template, same morning: `j.omondi`, `s.achieng`, `p.mutua`, `l.karanja`, `d.njoroge`... and `n.wanjiru`. Every decoy shows the same actor: `SubjectUserName: it.admin`. Then you reach the record for *this* departure:

![The 4725 record — the flag left in the SubjectUserName field](/public/images/the-last-day/07_flag.png)

```text
TargetUserName:   n.wanjiru
SubjectUserName:  r00t{th3_l4st_d4y_1ns1d3r_thr34t}
```

Whoever "handled the paperwork" left the flag **in the actor field of the account-disable record itself**. HR's own paperwork was the hiding place. That's the kind of touch that makes a forensics challenge memorable.

To be sure it was the only one: regex the raw bytes of both files for any `r00t{...}` — both UTF-16 byte alignments, both encodings. Exactly **one** flag exists in the entire dataset, and it only survives as a raw byte string inside that hidden record.

## Step 7 — Scoreboard

![All seven answers accepted — 7/7, 400/400](/public/images/the-last-day/08_answers.png)

| Q | Answer | Where it hid |
|---|---|---|
| Q1 | `r00t{n.wanjiru}` | visible 4624, LogonType 10 |
| Q2 | `r00t{203.0.113.77}` | visible 4624, IpAddress |
| Q3 | `r00t{F:\Staging}` | hidden Sysmon EID 11 + the 7z command line |
| Q4 | `r00t{client_exports_final.7z}` | hidden Sysmon EID 1, CommandLine |
| Q5 | `r00t{vault-personal-sync.io}` | hidden Sysmon EID 3, DestinationHostname |
| Q6 | `r00t{2026-09-14 00:07:22}` | hidden Sysmon EID 3, TimeCreated |
| Q7 | `r00t{th3_l4st_d4y_1ns1d3r_thr34t}` | hidden 4725, SubjectUserName |

**7/7 — 400/400.**

<div class="dr-callout ok">
  <span class="t">Format gotcha for anyone playing this platform</span>
  <p><strong>Every answer needs the <code>r00t{...}</code> wrapper</strong>, not just the final flag. Five of mine bounced before I wrapped them. Don't be me.</p>
</div>

## Noise That Eats Your Time

Half of forensics is knowing what to ignore. This challenge scatters decent decoys:

<div class="dr-traps">
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> C:\ProgramData\Intel\CV.exe + wwlib.dll</span>
    An unsigned binary masquerading as Intel graphics, spawning <code>calc.exe</code>. Genuinely suspicious-looking — but it's set dressing, not the story.
    <span class="truth">not connected to the staged files</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> lync.zip + i.exe + cmdkey.exe</span>
    A whole separate malware chain, timestamped at midnight. Credential juggling that goes nowhere near <code>F:\Staging</code>.
    <span class="truth">a different campaign, not this incident</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> nc.exe → 127.0.0.1:9299</span>
    A netcat connection to <em>localhost</em>. Not exfiltration — just a local listener.
    <span class="truth">loopback traffic, nothing leaves the host</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> The UtcTime fields inside Sysmon events</span>
    <code>2020-10-17</code>, <code>2020-08-02</code>... stale template junk the author never patched. The real story timeline lives in <code>TimeCreated</code>.
    <span class="truth">template leftovers, will lead you to 2020</span>
  </div>
</div>

The thread that never breaks: **`n.wanjiru`'s session, 02:47 → 03:07**.

## The Full Carve Script

The one that recovers records Event Viewer can't — including the cross-chunk template pooling:

```python
#!/usr/bin/env python3
"""Carve every recoverable record from a hand-crafted EVTX file.
Pools templates across chunks so cross-chunk template references resolve."""

import struct
import Evtx.Evtx as evtx
from Evtx.Evtx import Record

class PoolChunk:                       # stand-in chunk with every template
    def __init__(self, templates):
        self._offset = 0
        self._templates = templates
    def templates(self):
        return self._templates

def carve_offsets(buf):
    """scan raw bytes for record magic, walk by declared size, check footer"""
    offs, seen, n, i = [], set(), len(buf), 0
    while i < n - 28:
        if buf[i:i+4] == b'\x2a\x2a\x00\x00':
            size = struct.unpack_from('<I', buf, i+4)[0]
            if (24 <= size <= 0x10000 and i + size <= n
                    and struct.unpack_from('<I', buf, i+size-4)[0] == size):
                if i not in seen:
                    seen.add(i); offs.append(i)
                i += size
                continue
        i += 1
    return offs

path = 'Security.evtx'
log = evtx.Evtx(path)
log.__enter__()
buf = log._fh._buf

# 1. pool templates from every chunk
pool_templates = {}
for ch in log.chunks():
    try:
        pool_templates.update(dict(ch.templates()))
    except Exception:
        pass
pool = PoolChunk(pool_templates)

# 2. render every carved record (pooled fallback for cross-chunk refs)
seen = set()
for off in carve_offsets(buf):
    try:
        xml = Record(buf, off, pool).xml()
    except Exception:
        continue
    if xml not in seen:
        seen.add(xml)
        print(xml)
```

Dependencies: `pip install python-evtx`. The rest is standard library.

## Why You Should Care at 2 AM (Defender Notes)

This challenge is fiction, but every technique in it shows up in real insider incidents.

1. **Offboarding windows are attack windows.** The last days of employment are when data theft peaks — and "routine offboarding" is exactly when nobody looks twice. If HR and log review don't talk to each other, you're running on hope.
2. **Renamed binaries are free.** `wsus.exe` in a user profile, `CV.exe` pretending to be Intel — Masquerading (T1036) costs an attacker nothing and defeats naive "is this a known-good process?" checks. Check *paths*, not just names.
3. **Archivers don't phone home.** `7z.exe` opening a TCP socket is a five-alarm anomaly. Baseline which processes legitimately make outbound connections and alert on the rest.
4. **EVTX files can lie by omission.** Tampered logs with stripped chunk headers hide records from every tool that trusts the file's index. When counts and file sizes disagree, carve.

### Detection Tells

The same ones this challenge exhibited:

- **RDP logons (4624, LogonType 10) outside business hours** for accounts flagged for departure
- **4663 file access to sensitive shares** from processes whose paths don't match their names
- **Sysmon EID 1** with archive tooling in the command line (`7z a -p`, especially `-p`)
- **Sysmon EID 3** from any process that should never touch the network
- **File size vs. event count mismatch** in exported EVTX files — a tampering tell
- **4725/4726 account changes** where the actor field doesn't match the expected admin workflow

One after-hours RDP login is a coincidence. An after-hours RDP login, a staging folder, a password-protected archive, and an upload to a personal "sync vault" in twenty minutes is a filing cabinet leaving the building — with HR signing the paperwork on the way out.

## Recap — Seven Moves

| Step | Action |
|---|---|
| 1 | Notice the file sizes don't match the event counts |
| 2 | Spot the after-hours RDP logon (Q1 + Q2) |
| 3 | Carve the EVTX — Event Viewer can't show what's inside |
| 4 | Find the Finance access via a renamed `wsus.exe` |
| 5 | Catch the `7z a -p` archive command (Q3 + Q4) |
| 6 | Catch the upload to `vault-personal-sync.io` (Q5 + Q6) |
| 7 | Read HR's paperwork — the flag is in the record (Q7) |

HR said it was routine. The logs — all 78 of them, not just the 13 that render — said otherwise.

**Trust the carve.**

---

*Tooling: python-evtx + a raw-bytes carve (full script above). All visuals recreated from the actual event data.*

*— Frank Ngaruiya (@z3r0bme)*
