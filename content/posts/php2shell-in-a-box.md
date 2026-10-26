---
title: "PHP2Shell in a Box: Building a Local Lab for CVE-2026-109618 and CVE-2026-109619"
date: 2026-10-26
draft: false
description: "The two 9.2-critical RCEs fixed in PHP 8.2.35 through 8.5.12 on October 21, 2026, deserve more than a CVE skim. Here is how I stood up the exact vulnerable runtime (PHP 8.5.11 as mod_php, default settings) on a laptop, what the trigger actually looks like on the wire, and where the honest line between 'condition reproduced' and 'server owned' sits."
tags: ["PHP", "RCE", "CVE", "Vulnerability Research", "Lab"]
categories: ["Web"]
authors: ["z3ro"]
---

**Public lab:** [github.com/Frankie7techy/php2shell-lab](https://github.com/Frankie7techy/php2shell-lab)

When the PHP security release dropped on October 21, two details made everyone's
hair stand up: the bugs sit in code that **every request touches** (memory
management and error handling), and one of the confirmed exploits fires
**before any application code runs**. Not "your sloppy WordPress plugin ran it",
not "your framework forgot to escape". The runtime itself, with default
settings, on Apache with mod_php.

That combination, unauthenticated plus runtime-level plus default-settings, is
why the patch race mattered. So instead of skimming the advisories, I built the
runtime.

## Getting the bug back

The first obstacle is that you cannot install a vulnerable PHP anymore.
Distributors received the fix before disclosure: Ubuntu 26.04's
`8.5.4-0ubuntu1.5` looks like an older version but its changelog literally
contains `CVE-2026-109618_109619.patch`. The version string lies; the patch
does not.

That means: build it yourself. The lab's `setup-wsl.sh` downloads the genuine
`php-8.5.11.tar.gz` (the last vulnerable 8.5 release), configures it with
`--with-apxs2` for Apache mod_php, and installs it next to a stock
`php.ini-production`. Fifteen minutes later you have the highest-risk setup
the PHP security team described, serving on `127.0.0.1:8080`.

One deliberate choice in `apache-lab.conf`: the prefork pool is small
(StartServers 2, MaxRequestWorkers 8). Both bugs require the producer and
consumer of the corruption to **land on the same worker process**, and small
pools are what the confirmed exploitations assumed.

## What the bug looks like on the wire

The interesting half is CVE-2026-109618, the OOM corruption. PHP handles
`memory_limit` exhaustion by `longjmp()`-ing out of the current context. If
that jump happens while request memory is reachable but not fully initialized,
cleanup later reads and branches on garbage. The advisory lists the winning
condition plainly: an OOM **during multipart parsing**, not during script
execution.

There is a catch that took some empirical prodding. The default limits fight
each other:

- `post_max_size = 8M` rejects big bodies **before** parsing,
- `max_multipart_body_parts = 1020` caps the part count,
- `max_input_vars = 1000` caps the variable count,
- and 128M of `memory_limit` is a long way from an 8M body.

The way through is on the advisory's own list: send the body with
**`Transfer-Encoding: chunked` and no `Content-Length`**. Without a
Content-Length, the pre-parse `post_max_size` check never fires, and the
rfc1867 parser keeps consuming whatever you send. Verified directly: an
18.8 MB body got rejected with `Content-Length`, and sailed into the parser
without it (the parser's own limit warnings show up in the error log for the
chunked case only).

Now the amplification: ~1000 parts, each with a 128-512 KB **part name**.
Parsed memory runs at roughly 1.2x wire size, and chunked removes the wire
ceiling, so ~150-600 MB of symbol table allocations walk into a 128M limit.
The OOM fires mid-parse:

```
PHP Fatal error: Allowed memory size of 134217728 bytes exhausted
(tried to allocate 135168 bytes) in Unknown on line 0
Stack trace: #0 {main}
```

Read that carefully, because it is the whole story in four lines. `in Unknown
on line 0` and `#0 {main}` mean the fatal fired in **request startup**, inside
the multipart parser, before `index.php` executed a single line. The longjmp
the patch removes is exactly the one this escape hatch is taking.

In the verification run, **471 of 471 trigger requests** landed in this state.
The trigger is deterministic. The corruption is not, which is the next
section.

## The honest line

Full RCE needs the failed allocation to land at precisely the wrong moment,
with the heap shaped the right way. The researchers demonstrated it; the CVSS
says `AC:H` for a reason. Across ~470 draws with varied part-name sizes
(sampling different failure points inside the parse), the lab produced **zero
worker segfaults and zero heap-corruption aborts**. The same held for the
CVE-2026-109619 producer-consumer pairs: both producer paths are provably live
with defaults (session upload progress tracking, fatal-error backtraces in the
log), but 200 pairs did not produce a crash correlation.

That is the point of publishing the lab with honest numbers. The public PoC
pile for these CVEs is mostly noise (watchTowr's summary: the sprayed exploits
"don't work at all, test for timing-based differences, or crash the target",
and JFrog found some laced with malware). What the lab gives you instead is
the **deterministic pre-condition** and a harness to iterate on the
probabilistic part without pointing any of it at servers you do not own.

## What to actually do

- Patch: 8.5.12, 8.4.27, 8.3.36, or 8.2.35. Version strings on distro packages
  can lie; check the changelog.
- PHP 8.1 and older are **never getting a fixed release**. Treat them as
  permanently vulnerable.
- Stopgap for the OOM bug: enforce `memory_limit=-1` at the pool/vhost level
  and keep `post_max_size` low. For the stale-state bug:
  `session.upload_progress.enabled=0` and on 8.5
  `fatal_error_backtraces=0`. All incomplete, all better than nothing.
- Detection hint from the lab work: chunked POST bodies to PHP endpoints with
  no `Content-Length` are not a normal client pattern, and requests producing
  `Allowed memory size ... in Unknown on line 0` are this trigger or something
  shaped like it. Amazon's MadPot telemetry puts the first exploitation
  attempts at **October 17**, four days before disclosure; if you run PHP,
  review logs from that date, not from the advisory date.
