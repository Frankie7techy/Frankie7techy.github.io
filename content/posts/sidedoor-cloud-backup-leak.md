---
title: "Sidedoor: The Cloud Backup That Was Uploading the Secret"
date: 2026-10-18
draft: false
description: "A pcap full of normal traffic and one host quietly posting a backup file to a cloud sync endpoint over plain HTTP. The recovery token is in the upload. No crypto required."
tags: ["CTF", "r00t CTF", "Network Forensics", "HTTP"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Forensics</span>
    <span class="dr-badge cyan">Network</span>
    <span class="dr-badge ghost">r00t CTF :: Sidedoor</span>
  </div>
  <div class="dr-title">SIDEDOOR</div>
  <p class="dr-sub">A backup client that shipped a recovery token to a cloud sync service over plain, unauthenticated HTTP. The breach and the evidence are the same packet.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n">3692</span><span class="l">packets</span></div>
  <div class="dr-stat"><span class="n">94</span><span class="l">seconds of capture</span></div>
  <div class="dr-stat"><span class="n red">1</span><span class="l">odd host</span></div>
  <div class="dr-stat"><span class="n cyan">0</span><span class="l">decryption steps</span></div>
</div>

![Sidedoor pipeline](/public/images/sidedoor/00_chain.svg)

## The handout

A single capture, `capture.pcap`, about 3700 frames over ninety seconds. The task is the classic one: something left the network that should not have, find it.

Most of the traffic is boring and deliberately so: DNS, TLS to the usual CDNs, background chatter. The trick is that the interesting host is not exotic. It talks to `sync.cloudbackup-service.net`, which sounds exactly like something a managed laptop would be allowed to talk to. That is the point of a side door.

## Filters that pay off

Before reaching for anything clever, reduce the haystack:

```text
http
http.request.method == "POST"
tcp.port != 443 && http
```

The last one is the highest-value filter on almost every traffic challenge. Anything speaking cleartext HTTP to a non-standard port on a modern network deserves a look. Here it lands on a single POST to a cloud sync endpoint.

![HTTP upload](/public/images/sidedoor/01_http.png)

## Reassembling the upload

Wireshark's HTTP object export does the whole job. In `tshark` terms:

```bash
tshark -r capture.pcap --export-objects http,/tmp/sd -q
```

That writes out every HTTP body it can reassemble. The body of interest is a `multipart/form-data` upload:

```text
POST /cloud-sync/upload?session=8f2e1a HTTP/1.1
Host: sync.cloudbackup-service.net
Content-Disposition: form-data; name="file";
  filename="quarterly_designs_backup.txt"

PROJECT ARCHIVE BACKUP -- INTERNAL USE ONLY
recovery-token: r00t{th3_cl0ud_sync_th4t_w4snt}
```

The backup client is doing exactly what a backup client does: posting a file to its service. The problem is that the file is a project archive, the transport is HTTP with no TLS, and the file contains a `recovery-token` line in plain sight. Every layer of this is a finding:

- the traffic is unencrypted, so anyone on the path can read it
- the endpoint takes an arbitrary file with no authentication visible in the request
- the file itself carries a secret

![flag](/public/images/sidedoor/02_flag.png)

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{th3_cl0ud_sync_th4t_w4snt}</code>
</div>

## The lesson

Forensics challenges love to dress up a plaintext leak as a "the attacker used a weird protocol" story. Most of the time it is simpler than that: something that should have been encrypted was not, and something that should not have been in a backup was.

The workflow to keep:

- Sort by protocol, then by destination. Legitimate-looking hosts are where side doors live.
- Cleartext HTTP on a non-standard port is the single best filter in your toolbox.
- Export objects before you read packets by hand. Reassembly tools have already solved `Content-Length`, retransmissions and chunking for you.

The flag is a confession. `th3_cl0ud_sync_th4t_w4snt` says it all: the cloud sync service was not a cloud sync service at all. It was the exfiltration channel, and the client was more than happy to help.
