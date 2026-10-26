---
title: "PHP2Shell in a Box: Reproducing CVE-2026-109618 and CVE-2026-109619 on a Laptop"
date: 2026-10-26
draft: false
description: "The two 9.2-critical runtime RCEs fixed in PHP 8.2.35 through 8.5.12 on October 21, 2026 touch code every request runs. I rebuilt the exact vulnerable runtime (PHP 8.5.11 compiled as mod_php, default settings), found the request shape that detonates memory_limit mid-parse, and mapped where the honest line between 'condition reproduced' and 'server owned' actually sits."
tags: ["PHP", "RCE", "CVE", "Vulnerability Research"]
categories: ["Web", "Research"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Research</span>
    <span class="dr-badge red">CVSS 9.2 x2</span>
    <span class="dr-badge cyan">RCE</span>
    <span class="dr-badge ghost">PHP 5.4 - 8.5.11 · patched 2026-10-21</span>
  </div>
  <div class="dr-title">PHP2SHELL</div>
  <p class="dr-sub">Two critical remote-code-execution bugs in the PHP <strong>runtime</strong> itself, in code that every single request touches. One fires before your application runs a line. Here is the build log: recompiling the exact vulnerable runtime, finding the request shape that reaches the bug, and finding out which part is deterministic and which part is a lottery.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n red">471</span><span class="l">in-parse OOM fatals</span></div>
  <div class="dr-stat"><span class="n cyan">0</span><span class="l">worker crashes (honest)</span></div>
  <div class="dr-stat"><span class="n">1020</span><span class="l">parts per trigger</span></div>
  <div class="dr-stat"><span class="n">Oct 17</span><span class="l">first observed exploitation</span></div>
</div>

**The lab, with all scripts and raw logs:** [github.com/Frankie7techy/php2shell-lab](https://github.com/Frankie7techy/php2shell-lab)

## The disclosure nobody got to plan

On October 20 the CVE identifiers started circulating on forums with a wrong release date and a wrong CVSS of 10.0. No technical details leaked with them, but the countdown had escaped the room. The PHP project pulled its release forward a full day and shipped the fixes on October 21 in 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Both issues score 9.2 under CVSS v4.0.

The post-disclosure details are what made this one feel different from a normal patch Tuesday:

- The research came out of **Wiz**, with their writeup crediting mixed model assistance, including Gemini 4 Argon on exploit development and patch validation.
- **Amazon MadPot** telemetry caught an exploitation attempt on **October 17**, four days before disclosure, from an anonymized source, against a bug still under embargo.
- Cloudflare counted thousands of attempts before the announcement and **millions of requests within hours** after it.
- CISA, CERT-EU and a joint ENISA / Europol / CSIRTs statement all pushed emergency patching the same day. The NCSC-NL runs a [php2shell repository](https://github.com/NCSC-NL/php2shell) just to track the software that embeds PHP and inherits the problem.

Patch-to-exploit latency for this one was measured in minutes, not weeks. That is the environment this writeup lives in.

## Two bugs, one patch release

![The amusement park ride: chunked body outruns the limits, OOM mid-parse](/public/images/php2shell-lab/00_oom_bypass.svg)

**CVE-2026-109618, RCE via out-of-memory.** PHP enforces `memory_limit` by `longjmp()`-ing out of the current context when a request exhausts its budget. In request-startup phases, like multipart upload parsing, some request memory is reachable before it is fully initialized. Take the `longjmp` at one of those moments and the early exit is not accounted for: request shutdown later reads and branches on memory nobody finished setting up. The allocation that fails does not even need to be the corrupted one.

**CVE-2026-109619, RCE via stale global state.** Workers keep global state between requests: error state, session state, extension state. That state is owned by one request and must be reset before its backing memory is freed. A fatal error, an upload-progress update, or a stray warning can leave a worker-global pointing at request memory that shutdown then frees. The next request on that same worker runs diagnostics and session handling *before* normal request initialization replaces the pointer, and consumes freed memory: use-after-free, worker crash, and with heap grooming, code execution as the worker account.

![Producer dies, shutdown skips the reset, next request on the same worker eats the freed chunk](/public/images/php2shell-lab/01_stale_state.svg)

The bridge between the two bugs matters: `fatal_error_backtraces` on PHP 8.5 is both a stale-state producer and an OOM-adjacent path, which is why the confirmed mod_php exploitation chains them.

## Trap one: the version string lies

First thing I tried was installing a vulnerable PHP from distro packages. Ubuntu 26.04 offers **8.5.4**, and 8.5.4 is well below the patched 8.5.12, so it should be vulnerable, right? Wrong. The full package version is `8.5.4-0ubuntu1.5`, and that `-ubuntu1.5` is the tell. Debian-family security teams backport fixes into the old version number, and the changelog on the downloaded `.deb` spells it out:

```
php8.5 (8.5.4-0ubuntu1.5) resolute-security; urgency=medium

  * SECURITY UPDATE: Remote RCE via state corruption issue
    - debian/patches/CVE-2026-109618_109619.patch: Avoid state corruption
      via bailout in Zend/tests/bug40770.phpt, ...
    - debian/patches/CVE-2026-109618_109619-pre1.patch: ext/filter: fix
      use-after-free in parse_str() with filter.default ...
```

So the distro package was already patched days after disclosure. Every audit script that greps `php -v` for "8.5.4" and calls it vulnerable is wrong, and every one that greps for ">= 8.5.12" is also wrong, because `8.5.4` plus backported patches is fixed. On distro systems the changelog is the truth, the version string is a rumor.

For the lab this means compile from source. `setup/setup-wsl.sh` pulls the genuine `php-8.5.11.tar.gz` (the last vulnerable 8.5 release), configures `--with-apxs2`, and installs it as an Apache module on port 8080. One deliberate choice in the vhost: a small prefork pool. Both bugs need the producer and consumer requests to **land on the same worker process**, and a pool of eight workers is the realistic worst case the confirmed exploits assumed.

## What the trigger looks like on the wire

The default settings form a wall, and reading the wall is most of the work:

| Limit | Default | Effect |
|---|---|---|
| `post_max_size` | 8M | rejects big bodies before parsing |
| `max_multipart_body_parts` | 1020 | caps part count |
| `max_input_vars` | 1000 | caps counted variables |
| `memory_limit` | 128M | the tripwire, 16x above post_max_size |

Sending a 100 MB body with `Content-Length` just gets rejected pre-parse:

```
PHP Warning: POST Content-Length of 18788902 bytes exceeds
the limit of 8388608 bytes in Unknown on line 0
```

The advisory's own strategy list names the way past it: **`Transfer-Encoding: chunked`, no `Content-Length`**. There is nothing for the pre-parse check to compare against, and the rfc1867 parser keeps reading whatever arrives. Same 18.8 MB body, chunked instead: parsed, with the parser's own limit warnings firing in the log.

Amplification is the second half. Part *names* are the cheapest bytes in a multipart body and the most expensive to parse, since each one is copied into symbol tables. Empirically the parsed size runs at about **1.2x wire size**, not the 100x I first guessed, so the math has to close the gap to 128M on the wire side: ~1000 parts under the parts cap, 128 to 512 KB of name per part, and chunked removes the wire ceiling. 150 to 600 MB of parsed allocations walk into a 128M budget.

The result is mathematically boring and forensically loud. Every trigger request dies with this, and every one of these four lines is load-bearing:

```
PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted
(tried to allocate 135168 bytes) in Unknown on line 0
Stack trace:
#0 {main}
```

`in Unknown on line 0` and `#0 {main}` mean the fatal fired in **request startup, inside the multipart parser, before index.php executed a single line**. That is the exact bail-out path the patch removes: the `longjmp` out of a context where request memory was reachable but not finished being built.

One honest war story from the harness itself: my first "400 burst" campaign produced one OOM instead of four hundred, because the body's multipart boundary (`cln<seq>`) disagreed with the header (`cln0`) and the parser silently gave up on 399 requests. Both harness bugs I hit were boundary-agreement bugs, which is its own tiny lesson about protocols carried in prose.

<div class="dr-callout danger">
  <span class="t">The deterministic part</span>
  <p>471 of 471 trigger requests hit in-parse OOM exhaustion across three campaigns, with part-name lengths 128-512 KB sampling different failure points inside rfc1867. Reaching the bail-out the patch removes is reproducible on demand. The lab relies on that; the RCE chain builds on top of it.</p>
</div>

## The crash lottery, stated honestly

Full control-flow hijack needs the failed allocation to land at precisely the wrong moment with the heap shaped right. The researchers demonstrated it. The CVSS says `AC:H`, attack complexity high, for a reason. Across ~470 in-parse OOM draws the lab produced **zero worker segfaults and zero heap-corruption aborts**, and 200 producer-consumer pairs on the CVE-2026-109619 side produced no crash correlation either, though both producer paths are provably live on defaults (backtraced fatals in the log, upload-progress tracking active).

That outcome is not a failure of the bug and not a failure of the lab. It is the measured distance between "the bail-out happens" and "the bail-out corrupts something useful", and it is exactly the number you cannot get from an advisory.

The public PoC pile deserves its own warning label. watchTowr's read on the flood: the sprayed exploits "either don't work at all, test for timing-based differences, or crash the target". JFrog found fake PoCs and prank malware on GitHub within hours. Recorded Future traced the most-shared PoC scripts to a theory their own author later invalidated. If the exploit you are holding came off a GitHub search page, the malware is more likely to work than the exploit.

## Detection, from the lab outward

What the lab run actually looked like in logs, as detection material:

- **`Allowed memory size ... in Unknown on line 0`**: memory_limit exhaustion during request initialization is not a normal application failure mode. Application code that exhausts memory names the script and the line. This signature names neither.
- **Chunked POST to a PHP endpoint with no `Content-Length`**: browsers do not send chunked bodies. Neither does curl unless you tell it to. The trigger depends on it.
- **`PHP_SESSION_UPLOAD_PROGRESS` in a POST body**: the confirmed FPM-side vector's fingerprint.
- **The log horizon is October 17**, not the advisory date. Amazon's telemetry confirms exploitation attempts before disclosure, and compromise checks that start on October 21 start four days late.

## Mitigations that change the outcome

Ordered by what they actually buy you:

1. **Patch**: 8.5.12, 8.4.27, 8.3.36, 8.2.35. On distro packages, verify the changelog, not the version string. PHP 8.1 and older never get a fixed release; the project published minimal source backports for 7.4 through 8.1 for people who build from source.
2. **`memory_limit=-1`, enforced at the pool or vhost level** (`php_admin_value`, not `.user.ini`): removes the attacker-controlled tripwire the OOM exploit needs. Incomplete, because an underlying allocation failure can still reach the vulnerable exit, but it kills the confirmed path.
3. **Keep `post_max_size` low and reject chunked-to-PHP at the proxy**: the wire-level wall the bypass in this post climbs. This is a stopgap, not a fix.
4. **`session.upload_progress.enabled=0` plus `fatal_error_backtraces=0` on PHP 8.5**, then restart every worker: dismantles both confirmed CVE-2026-109619 producers. ini_set at runtime does not help; the setting must be effective before request parsing.

## What the lab is for

The repository ships the builder, the target app, the trigger and probe harnesses, the detector, and the raw logs from these runs. Nothing in it points anywhere except loopback, and it deliberately ships no RCE. What it gives you is the deterministic half of the bug and a workbench for the probabilistic half: more draws, worker pinning, allocator notes, and a mitigation switchboard to flip settings and watch the trigger path change. That second half is where the interesting nights are.

## References

- [Advisory: RCE via OOM corruption (GHSA-w8hw-w9fx-j79w)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [Advisory: RCE via stale global state (GHSA-6wmf-4rv5-p3rp)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Foundation: the October 21 security release](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- [CISA alert: critical vulnerabilities in PHP require immediate patching](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- [Amazon threat intelligence: PHP2Shell exploitation before disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [Tenable: PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [Recorded Future: exploitation and PoC quality overview](https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation)
- [NCSC-NL php2shell: software that embeds PHP](https://github.com/NCSC-NL/php2shell)
- [The lab: Frankie7techy/php2shell-lab](https://github.com/Frankie7techy/php2shell-lab)
