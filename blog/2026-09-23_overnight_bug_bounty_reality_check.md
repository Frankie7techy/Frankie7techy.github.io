# The Overnight Bug-Bounty Trick from Twitter Works — Just Not How You Think

**Date:** 2026-09-23
**Author:** Frank — security research lab notes
**Classification:** Public, defensive research only

A post went around this week with a seductively simple recipe: download a big company's
public repos, list the dependencies, point an LLM at every one of them, fuzz everything,
report what falls out, collect $6,500. The replies were already laughing: step 8 is a Slack
message asking why you tested anything at all, step 9 is "the real bounty was the emotional
damage."

Here's the thing, though — I ran the experiment overnight anyway, because the recipe is
*almost* right. It's missing the only step that matters. This is the honest version of
what happened, numbers included.

## What the tweet gets right

Public source code is the most under-priced attack surface in the world. You don't need
anyone's permission to read it, the bug classes repeat across projects, and an LLM
genuinely compresses the loop of "grep for a dangerous sink → trace the data flow →
form a hypothesis" from hours to minutes. Aiming that loop at the long tail of an
ecosystem (small dusty dependencies, not the flagship repos a thousand researchers already
combed) is a real, working strategy. My lab has one verified critical vulnerability from
exactly this pipeline sitting in the disclosure queue right now — details withheld until
the private report resolves, as they should be.

## What the tweet skips: verification is 90% of the work

An LLM saying "this looks injectable" is not a bug. A bug is a transcript: the exact
source, the exact input, the observable effect, replayed from a cold start. And before
you file anything you owe the maintainer a dedup pass — is this function already covered
by a published CVE for a different component or version range? Skipping that step is how
you become a reply-guy story.

If you can't replay it, you don't have it. That's the whole job.

## What actually found a bug last night: my own code

The fastest legitimate "find a real bug before sunrise" target isn't somebody's trillion
dollar attack surface. It's the parser you wrote last week and never threw garbage at.

My lab maintains a small static binary-analysis toolkit (`bin_scanner`). I wrote a tiny
deterministic mutation fuzzer for its PE parser — a seed built from the unit test's
synthetic PE, six mutation operators (truncation, byte flips, interesting 32-bit values,
`e_lfanew` games, magic-field swaps, junk append), and one oracle: *the parser may return
a result or raise our own `PEParseError`. Anything else is a defect.*

Five thousand iterations in, it landed in a window my static review had predicted but
hadn't proved. The optional-header guard checked the buffer was at least `opt_offset + 24`
bytes long — but `image_base` is read at offset `+28` (PE32) or as a qword at `+24`
(PE32+). Any file truncated to 176–183 bytes sailed past the guard and died in
`struct.unpack_from`, leaking a raw `struct.error` to callers instead of a clean
rejection. Two unique crash signatures in 30,000 iterations, repro buffers saved.

```python
# before: struct.error escapes on a 176..183-byte file
if len(data) < opt_offset + 24:   # image_base read needs opt_offset + 32
# after:
if len(data) < opt_offset + 32:
    raise PEParseError("File too short for Optional header")
```

One-line fix, regression tests for both magic variants, a second small guard so the CLI's
`--window 0` stops dying with an opaque `range()` error, and a post-fix campaign of
37,500 iterations with zero unexpected exceptions. Suite: 9/9 green.

Is it a CVE? No. It's a length-guard off-by-eight in my own tool, severity: embarrassing.
Is it *real*? Completely — a fuzzer-driven, test-backed, permanently-closed defect found
in one night for zero dollars. The technique is identical to the one that finds them in
other people's code. You practice where it's free.

## The long-tail sweep, honestly reported

Same night, same method, pointed at a bucket of small MCP-servers I'd cloned earlier:

- Every template-literal `exec()` / `execSync()` hit re-triaged: all three were fed by
  *operator-side* config paths, never by tool-call arguments. Reachability is everything.
- A Docker-backed code-runner server: its `sh -c` command builder only escapes double
  quotes — backticks and `$()` go straight through. A finding? No. The tool exists to run
  the operator's code; injecting into your own payload crosses no boundary.
  (Network-isolated, memory-capped containers; missing PID limits and capability drops
  are hardening notes, not vulnerabilities.)
- A "DOM shell": a Chrome extension with no process-execution surface at all.

Zero new CVEs. That's not a failed night — that's what most audit nights look like. The
deliverable isn't always a bug; sometimes it's a documented list of things you no longer
have to wonder about.

## The actual recipe

1. Pick an ecosystem you understand; clone its long tail, not its flagships.
2. Sweep dangerous sinks (`exec` with template literals, `spawn(shell:true)`, archive
   extraction, SSRF guards), then *trace data flow* before believing anything.
3. Verify empirically: run the real handler locally with a mocked request, keep the
   transcript, save the repro.
4. Dedup against existing CVEs per component and version range.
5. File privately (GitHub private vulnerability reports take minutes). *Then* the 90-day
   clock starts — not before.
6. And first, before all of it: fuzz your own code. Last night the only guaranteed-find
   bug in the building was mine.

The tweet's punchline is right about one thing: nobody hands you the $6,500 for step 3.
What you actually collect overnight is a tighter feedback loop, a cleaner codebase, and —
if you're disciplined about evidence — occasionally a report that survives triage.

---
*Defensive research only. No third-party systems were tested; all auditing was performed
against local copies of public source code and first-party tooling. Details of the queued
finding are withheld pending coordinated disclosure.*
