---
title: "BlackGateWatch: A DNS Tunnel Hiding in Plain Sight"
date: 2026-10-18
draft: false
description: "Three thousand frames of ordinary corporate DNS, and one workstation quietly hex-encoding data into subdomains of its own domain. No TXT records, no long labels, no obvious tell."
tags: ["CTF", "r00t CTF", "Network Forensics", "DNS", "Exfiltration"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Forensics</span>
    <span class="dr-badge cyan">Network</span>
    <span class="dr-badge ghost">r00t CTF :: BlackGateWatch</span>
  </div>
  <div class="dr-title">BLACKGATEWATCH</div>
  <p class="dr-sub">Thousands of boring DNS lookups to real services, and one host tunnelling hex out through subdomains it registered itself. The data is not in the payload. It is the query name.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">653</span><span class="l">query names</span></div>
  <div class="dr-stat"><span class="n red">3</span><span class="l">that matter</span></div>
  <div class="dr-stat"><span class="n cyan">1</span><span class="l">relay domain</span></div>
  <div class="dr-stat"><span class="n">0</span><span class="l">TXT records</span></div>
</div>

![BlackGateWatch pipeline](/public/images/blackgatewatch/00_chain.svg)

## The handout

A packet capture of a corporate network, and a flattened list of every query name in it. Most of it is the whitest noise imaginable: `outlook.office365.com`, `api.slack.com`, `github.com`, `graph.microsoft.com`, `zoom.us`. If you skim, you fall asleep.

Sorting the unique query names and looking at the shape of them is the move:

```bash
tshark -r dns_tunnel.pcap -Y 'dns.flags.response==0' \
    -T fields -e dns.qry.name | sort -u
```

Three names stand out, because they are nothing like the rest:

```text
000.723030747b646e735f74756e6e336c73.relay.blackgate-watch.net
001.5f63347272795f6d3072335f7468346e.relay.blackgate-watch.net
002.5f717533723133737d.relay.blackgate-watch.net
```

![DNS queries](/public/images/blackgatewatch/01_dns.png)

## Reading the pattern

Three structural tells, and together they are damning:

- **A fixed relay domain.** All three share `relay.blackgate-watch.net`, a domain the organisation did not appear to resolve for any other purpose.
- **An ordered sequence label.** `000`, `001`, `002`. That is a chunk index, not a real hostname. It tells you both the order and that more chunks might have been expected.
- **A hex-encoded payload label.** The middle label is the giveaway. `723030747b646e735f74756e6e336c73` is not a word. It is hex, and it decodes to ASCII starting with `r00t{`.

That third point is the whole trick. This tunnel does not use DNS `TXT` records, which is what most detection rules and most writeups assume. It smuggles the data in the *query name itself*, as a subdomain, which means the exfiltration looks like ordinary name resolution to anything that only inspects record type or record size.

## Decoding the tunnel

Concatenate the payload labels in sequence order and hex-decode:

```python
labels = [
    "723030747b646e735f74756e6e336c73",   # 000
    "5f63347272795f6d3072335f7468346e",   # 001
    "5f717533723133737d",                 # 002
]
print(bytes.fromhex("".join(labels)).decode())
```

```text
000  723030747b646e735f74756e6e336c73  r00t{dns_tunn3ls
001  5f63347272795f6d3072335f7468346e  _c4rry_m0r3_th4n
002  5f717533723133737d                 _qu3r13s}
```

![flag](/public/images/blackgatewatch/02_flag.png)

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{dns_tunn3ls_c4rry_m0r3_th4n_qu3r13s}</code>
</div>

## The lesson

DNS is the most permissive protocol on a corporate network, because almost nothing is blocked. A name has to be resolved for anything else to happen, so DNS is allowed out of almost every firewall, and the query name is attacker-controlled data that can be up to 253 characters long. It is a channel, not just a resolver.

What makes this challenge good is what it *avoids*:

- no `TXT` records, so record-type rules miss it
- short labels, so length-based heuristics do not fire
- a low volume of tunnel traffic drowned in real lookups, so volume thresholds do not trip
- a domain that blends in by choosing the word `relay`

When you are hunting this in the wild, the reliable tells are structural, not statistical: sequences (`000`, `001`), high-entropy labels, base32 or hex alphabets in subdomains, and subdomains that only ever appear as queries and never get a sensible answer. The name of the game is *dns tunnels carry more than queries*, and the capture said so all along.
