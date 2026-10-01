---
title: "Packet Whisperer — The One Where DNS Snitched on Itself"
date: 2026-09-23
draft: false
description: "DNS exfiltration reversed from a PCAP — pure Python, zero Wireshark. A complete walkthrough of how attackers smuggle data out via DNS TXT queries and how to catch them."
tags: ["CTF", "AfricaHackon", "Network Forensics", "DNS", "Exfiltration"]
categories: ["Forensics"]
authors: ["z3ro"]
---

## Challenge Overview

| Field | Value |
|---|---|
| **Platform** | AfricaHackon |
| **Challenge** | Packet Whisperer |
| **Author** | p3rf3ctr00t |
| **Category** | Network Forensics |
| **Difficulty** | Easy |
| **Points** | 100 |
| **Given** | `chall.pcap` (1,279 packets) |

> *"Analyze the provided PCAP and identify the hidden DNS-related flag."*

**Flag:** `r00t{1ts_4lw4y5_DNS_r1ght}`

---

## TL;DR

Someone slid a ZIP archive out of a network using nothing but DNS TXT queries. This writeup walks through exactly how to spot it and reverse it — zero Wireshark required (though it works there too).

**The six moves:**
1. Isolate port-53 traffic
2. Spot freaky TXT queries to `*.hackerman.com`
3. Strip the domain, glue labels into one base64 string per query
4. Concatenate in packet order, decode
5. `PK` magic → ZIP → extract
6. Read `flag.txt`, ignore the troll note, bank the points

---

## Step 0 — First Impressions

Opening a pcap blind is like walking into a room where everyone is talking at once: you don't listen to individuals, you listen for the *weird* voice.

The file is small (1,279 packets), and the description literally hands us the filter: **DNS**.

In Wireshark you'd type:

```
dns
```

I wanted to script this instead — sure enough, the "weird voice" would need a transform later. No tshark, no scapy on this box, so I wrote a tiny pure-Python pcap parser (pcaps are simple: 24-byte global header, then `[16-byte record header + raw frame]` repeating; carve Ethernet → IPv4 → UDP → port 53).

Full source: [dns_extract.py](/public/files/packet-whisperer/dns_extract.py)

---

## Step 1 — The "Wait, What?" Moment

![Suspicious DNS TXT queries found in the pcap](/public/images/packet-whisperer/01_suspicious_dns.png)

A neat burst of **TXT queries** for domains like:

```
UEsDBAoAAAAAAHKRelsO8+wGGwAAABsAAAAIABwA.hackerman.com
```

Three things set off the alarm:

1. **Nobody legitimately asks for TXT records of 50-character random-looking subdomains.** TXT is usually SPF/DKIM/verification — short, boring labels.
2. **The "random" strings aren't random.** The alphabet is `A–Z a–z 0–9 + /` with one `==` at the end of the final query. That's base64 staring at you.
3. **They're sequential and burst-y** — packets #1218 to #1250, fired off like a script.

---

## Step 2 — What We're Looking At: DNS Exfiltration

Here's the part worth understanding properly, because this technique shows up in real intrusions all the time:

> You don't choose the *destination* of a DNS query — the resolver chases it for you — but you fully control the *question*. If you own the authoritative nameserver for the domain, every question arrives at your doorstep, in order, logged forever.

So an attacker doesn't need HTTP, an open port, or anything a firewall blinks at. They just need DNS — the one thing every network lets through on port 53.

![How DNS exfiltration works, end to end](/public/images/packet-whisperer/02_exfil_diagram.png)

**The punchline for us:** the pcap contains the entire stolen file. Every query is a carrier pigeon, and the pcap caught all the pigeons. We only need to read the little scrolls in order.

---

## Step 3 — Carving the Chunks

Per query name, we only want what's before `.hackerman.com`. One gotcha: some chunks span **multiple DNS labels** (a label caps out at 63 chars), so strip the domain and rejoin the remaining labels *without dots*:

```python
if name.endswith(".hackerman.com"):
    b64 = name[:-len(".hackerman.com")].replace(".", "")
    chunks.append(b64)
```

Second gotcha: only collect **queries** (destination port 53). Responses echo the same names back — take both and you'll decode every chunk twice.

---

## Step 4 — The Blob Says Hello

Concatenate the chunks in packet order, `base64.b64decode`, and peek:

```
b'PK\x03\x04\n\x00\x00\x00\x00\x00r\x91z[...'
```

`PK` (Phil Katz) is the magic of every ZIP file on Earth. Which explains why the first chunk, `UEsDB...`, looked familiar all along — base64 of `PK\x03\x04` starts with `UEsDB`.

Hand the bytes to Python's `zipfile`:
[dns_decode.py](/public/files/packet-whisperer/dns_decode.py)

---

## Step 5 — Free Flag Inside

![Decoding the ZIP and revealing the flag](/public/images/packet-whisperer/03_flag_revealed.png)

The archive holds two files:

- **`notes.txt`** — *"Some random data, you are close though"* — a decoy and a bit of trolling from the author. Respect.
- **`flag.txt`** — the prize:

```
r00t{1ts_4lw4y5_DNS_r1ght}
```

Submitted. 100/100. Done.

---

## Why You Should Care at 2 AM (Defender Notes)

DNS exfiltration keeps working because of three uncomfortable truths:

1. **DNS is rarely inspected.** Firewalls obsess over HTTP/SMTP while port 53 strolls by.
2. **Query names are user-controlled by design.** Abuse looks exactly like use — until you check *volume and shape*.
3. **The authoritative server keeps a perfect ordered log.** The attacker just reads their own query log later.

### Detection Tells

The same ones this challenge exhibited:

- Labels at/near the **63-char limit** (padding maxes throughput)
- Bursts of **TXT/NULL/CNAME queries to one rare domain**
- High-entropy (base64-looking) names under a single parent domain
- Queries massively outnumbering answers

One weird query is a hiccup. Seventeen in a row at 63 chars each is a filing cabinet leaving the building.

---

## The Full Script

```python
#!/usr/bin/env python3
"""Pure-Python DNS exfiltration extractor — no scapy, no tshark."""

import struct
import base64
import zipfile
import io

def parse_pcap(filename):
    """Yield (timestamp, raw_frame) from a pcap file."""
    with open(filename, 'rb') as f:
        # Global header: 24 bytes
        gh = f.read(24)
        magic = struct.unpack('<I', gh[:4])[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            raise ValueError("Not a pcap file")

        while True:
            # Record header: 16 bytes
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', rh)
            frame = f.read(incl_len)
            yield (ts_sec + ts_usec / 1e6, frame)

def extract_dns_queries(pcap_file):
    """Extract DNS query names from a pcap file."""
    chunks = []
    for ts, frame in parse_pcap(pcap_file):
        # Ethernet (14) → IPv4 (20) → UDP (8)
        if len(frame) < 42:
            continue
        eth_type = struct.unpack('>H', frame[12:14])[0]
        if eth_type != 0x0800:  # Not IPv4
            continue
        ip_start = 14
        ip_header = frame[ip_start:ip_start+20]
        if len(ip_header) < 20:
            continue
        ip_proto = ip_header[9]
        if ip_proto != 17:  # Not UDP
            continue
        udp_start = ip_start + 20
        udp_header = frame[udp_start:udp_start+8]
        if len(udp_header) < 8:
            continue
        src_port, dst_port = struct.unpack('>HH', udp_header[:4])
        if dst_port != 53:  # Not a DNS query
            continue
        # DNS payload starts after UDP header
        dns_payload = frame[udp_start+8:]
        # Skip DNS header (12 bytes), parse question name
        name = parse_dns_name(dns_payload, 12)
        if name and name.endswith('.hackerman.com'):
            b64 = name[:-len('.hackerman.com')].replace('.', '')
            chunks.append(b64)
    return chunks

def parse_dns_name(data, offset):
    """Parse a DNS name from a packet."""
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        offset += 1
        labels.append(data[offset:offset+length].decode('ascii', errors='ignore'))
        offset += length
    return '.'.join(labels) if labels else None

if __name__ == '__main__':
    chunks = extract_dns_queries('chall.pcap')
    print(f"Found {len(chunks)} DNS chunks")
    blob = base64.b64decode(''.join(chunks))
    print(f"Decoded {len(blob)} bytes, magic: {blob[:4]}")
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        print(zf.namelist())
        print(zf.read('flag.txt').decode())
```

---

## Recap — Six Moves

| Step | Action |
|---|---|
| 1 | Isolate port-53 traffic |
| 2 | Spot freaky TXT queries to `*.hackerman.com` |
| 3 | Strip the domain, glue labels into one base64 string per query |
| 4 | Concatenate in packet order, decode |
| 5 | `PK` magic → ZIP → extract |
| 6 | Read `flag.txt`, ignore the troll note, bank the points |

It's always DNS. The flag said so itself.

---

*Scripts: [dns_extract.py](/public/files/packet-whisperer/dns_extract.py) · [dns_decode.py](/public/files/packet-whisperer/dns_decode.py)*

*— Frank Ngaruiya (@z3r0bme)*
