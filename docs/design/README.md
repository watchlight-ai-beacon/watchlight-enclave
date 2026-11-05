# Design notes

These are the notes you'd want before you trust a bundle, write a driver, or
tell us a decision here is wrong.

Start wherever your question is:

| If you're wondering… | Read |
|---|---|
| "what stops the agent from editing its own evidence?" | [trust-boundaries.md](trust-boundaries.md) |
| "what does a bundle actually prove?" | [evidence.md](evidence.md) |
| "why does my bundle say `incomplete`?" | [evidence.md](evidence.md#the-four-verdicts) |
| "what do all these control names mean?" | [attestation.md](attestation.md) |
| "what network traffic gets recorded?" | [egress.md](egress.md) |
| "I want to run this on something other than Docker" | [drivers.md](drivers.md) |
| "why is this limit 10,000?" | [limits.md](limits.md) |

## The one idea

Everything here follows from a single goal:

> **A bundle must never be able to understate what happened.**

Not "the bundle should be accurate" — something stronger. An inaccurate bundle
is a bug. A bundle that's *missing things while looking complete* is actively
dangerous, because people read a clean bundle as proof of innocence.

So we tilt everything in one direction. When a layer can't record, it stops
working instead of working silently. When a check can't be made, the bundle
says "couldn't check" instead of staying quiet. When there are two possible
readings, we record the pessimistic one.

There's a corollary that took us three review rounds to get right, and it's the
one worth internalising: **if the verifier only reads records that volunteer
information, then an empty bundle looks like a perfect bundle.** Silence has to
be a finding too, or the whole thing inverts. That's what
[the required-record floor](evidence.md#the-floor) is about.

## How a run actually works

```text
$ wl-enclave run --purpose "fix the login bug"
```

Seven steps:

**1. Validate the config.** Every problem at once, before anything exists. If
your `enclave.yaml` has four mistakes you get four error messages, not a
scavenger hunt. — `config.py`

**2. Set up the run directory** and open the hash chain. If a chain is already
there, verify it *before* appending to it (see
[why](evidence.md#verify-before-you-extend)). Record the digests of every file
that governs this run. — `runs.py`, `evidence.py`, `config.py`

**3. Start the egress guard.** Before the sandbox, not after — otherwise
there's a window where the agent is running and nothing is watching it. The
guard joins an internal Docker network (no route to the internet) *and* an
egress network, which makes it the only way out. We wait for the guard to say
`listening on` in its own logs before continuing. — `egress/local.py`

**4. Start the sandbox.** Read the constraints back out of Docker rather than
trusting that what we asked for is what we got. Confirm the evidence mask by
planting a file and trying to read it from inside. — `drivers/docker.py`

**5. The agent runs.** Two record streams, written independently:

```text
runs/<id>/evidence/    decisions, written by the agent via the SDK
runs/<id>/guard/       network attempts, written by the guard
```

**6. Shut down.** Send the guard SIGTERM so it writes its closing tally, then
read both streams in, record anything we had to drop at the boundary, and
cross-check the tallies against what's actually in the chain.

**7. Seal.** You get `bundle/chain.jsonl` and `bundle/manifest.json`, which
anyone can check with `wl-enclave verify` — no account, no network, no
Watchlight.

## Two witnesses, neither sufficient

Watchlight knows the agent *asked to wire money*. The guard knows it *tried to
reach pastebin.com*. You can't derive either from the other, which is why a
bundle carries both and why the attestation records how solidly each control
was established rather than just claiming "contained: true".

## What's not built yet

Saying this up front, because a design doc that reads like a description of a
finished system is a lie by omission.

- **Bundles aren't signed.** The chain proves it hasn't been *edited*. It does
  nothing about *truncation*, and it says nothing about who produced it. This
  is the biggest gap. Issues #2–#6.
- **Traffic the topology blocks isn't recorded.** If the agent opens a raw
  socket to port 9999, there's no route, so it fails — but the guard never sees
  it, so there's no record. The bundle admits this about itself rather than
  leaving you to discover it. Issue #12.
- **The workspace is writable**, so a run can edit the rules the *next* run is
  held to. We make it visible with digests rather than preventing it. Issue #13.
