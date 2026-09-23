---
title: "Packet Whisperer — The One Where DNS Snitched on Itself"
date: 2026-09-23
draft: false
tags: ["CTF", "AfricaHackon", "Network Forensics", "DNS", "Exfiltration"]
categories: ["Forensics"]
---

## Challenge Overview

- **Platform:** AfricaHackon — *Packet Whisperer* by p3rf3ctr00t
- **Category:** Network Forensics | **Difficulty:** Easy | **Points:** 100
- **Given:** a single file, `chall.pcap`
- **Task:** *"Analyze the provided PCAP and identify the hidden DNS-related flag."*

**Flag:** `r00t{1ts_4lw4y5_DNS_r1ght}`

The whole trick: someone slid a ZIP archive out of a network using nothing but
DNS TXT queries. This writeup walks through exactly how to spot it and reverse
it — zero Wireshark required (though it works there too).

---

## Step 0 — First impressions

Opening a pcap blind is like walking into a room where everyone is talking at
once: you don't listen to individuals, you listen for the *weird* voice. The
file is small (1,279 packets), and the description literally hands us the
filter: **DNS**.

In Wireshark you'd type:

```
dns
```

I wanted to script this instead — sure enough, the "weird voice" would need a
transform later. No tshark, no scapy on this box, so I wrote a tiny pure-Python
pcap parser (pcaps are simple: 24-byte global header, then `[16-byte record
header + raw frame]` repeating; carve Ethernet → IPv4 → UDP → port 53). Full
source: [dns_extract.py](/files/packet-whisperer/dns_extract.py)

---

## Step 1 — The "wait, what?" moment

![Suspicious DNS TXT queries found in the pcap](/images/packet-whisperer/01_suspicious_dns.png)

A neat burst of **TXT queries** for domains like:

```
UEsDBAoAAAAAAHKRelsO8+wGGwAAABsAAAAIABwA.hackerman.com
```

Three things set off the alarm:

1. **Nobody legitimately asks for TXT records of 50-character random-looking
   subdomains.** TXT is usually SPF/DKIM/verification — short, boring labels.
2. **The "random" strings aren't random.** The alphabet is `A–Z a–z 0–9 + /`
   with one `==` at the end of the final query. That's base64 staring at you.
3. **They're sequential and burst-y** — packets #1218 to #1250, fired off like
   a script.

---

## Step 2 — What we're looking at: DNS exfiltration

Here's the part worth understanding properly, because this technique shows up
in real intrusions all the time:

> You don't choose the *destination* of a DNS query — the resolver chases it
> for you — but you fully control the *question*. If you own the authoritative
> nameserver for the domain, every question arrives at your doorstep, in order,
> logged forever.

So an attacker doesn't need HTTP, an open port, or anything a firewall blinks
at. They just need DNS — the one thing every network lets through on port 53.

![How DNS exfiltration works, end to end](/images/packet-whisperer/02_exfil_diagram.png)

The punchline for us: **the pcap contains the entire stolen file.** Every query
is a carrier pigeon, and the pcap caught all the pigeons. We only need to read
the little scrolls in order.

---

## Step 3 — Carving the chunks

Per query name, we only want what's before `.hackerman.com`. One gotcha: some
chunks span **multiple DNS labels** (a label caps out at 63 chars), so strip
the domain and rejoin the remaining labels *without dots*:

```python
if name.endswith(".hackerman.com"):
    b64 = name[:-len(".hackerman.com")].replace(".", "")
    chunks.append(b64)
```

Second gotcha: only collect **queries** (destination port 53). Responses echo
the same names back — take both and you'll decode every chunk twice.

## Step 4 — The blob says hello

Concatenate the chunks in packet order, `base64.b64decode`, and peek:

```
b'PK\x03\x04\n\x00\x00\x00\x00\x00r\x91z[...'
```

`PK` (Phil Katz) is the magic of every ZIP file on Earth. Which explains why
the first chunk, `UEsDB...`, looked familiar all along — base64 of `PK\x03\x04`
starts with `UEsDB`.

Hand the bytes to Python's `zipfile`:
[dns_decode.py](/files/packet-whisperer/dns_decode.py)

## Step 5 — Free flag inside

![Decoding the ZIP and revealing the flag](/images/packet-whisperer/03_flag_revealed.png)

The archive holds two files:

- **`notes.txt`** — *"Some random data, you are close though"* — a decoy and a
  bit of trolling from the author. Respect.
- **`flag.txt`** — the prize:

```
r00t{1ts_4lw4y5_DNS_r1ght}
```

Submitted. 100/100. Done.

---

## Why you should care at 2 AM (defender notes)

DNS exfiltration keeps working because of three uncomfortable truths:

1. **DNS is rarely inspected.** Firewalls obsess over HTTP/SMTP while port 53
   strolls by.
2. **Query names are user-controlled by design.** Abuse looks exactly like use
   — until you check *volume and shape*.
3. **The authoritative server keeps a perfect ordered log.** The attacker just
   reads their own query log later.

Detection tells — the same ones this challenge exhibited:

- Labels at/near the **63-char limit** (padding maxes throughput)
- Bursts of **TXT/NULL/CNAME queries to one rare domain**
- High-entropy (base64-looking) names under a single parent domain
- Queries massively outnumbering answers

One weird query is a hiccup. Seventeen in a row at 63 chars each is a filing
cabinet leaving the building.

---

## Recap — six moves

1. Isolate port-53 traffic.
2. Spot freaky TXT queries to `*.hackerman.com`.
3. Strip the domain, glue labels into one base64 string per query.
4. Concatenate in packet order, decode.
5. `PK` magic → ZIP → extract.
6. Read `flag.txt`, ignore the troll note, bank the points.

It's always DNS. The flag said so itself.

---

*Scripts: [dns_extract.py](/files/packet-whisperer/dns_extract.py) ·
[dns_decode.py](/files/packet-whisperer/dns_decode.py)*
