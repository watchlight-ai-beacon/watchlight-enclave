# Design

How Enclave is built and why. Written for someone deciding whether to trust a
bundle, extend a driver, or argue with a decision made here.

| Document | What it covers |
|---|---|
| [trust-boundaries.md](trust-boundaries.md) | who can influence what, and the one path the agent controls |
| [evidence.md](evidence.md) | the chain, the four verdicts, the record vocabulary |
| [attestation.md](attestation.md) | named controls, how each state was established, which claim it bears on |
| [egress.md](egress.md) | the guard, address validation, and what the records do and do not cover |
| [drivers.md](drivers.md) | the extension seam, and what a second runtime must deliver |
| [limits.md](limits.md) | every bound, with the reasoning and the failure it prevents |

## The claim everything serves

**A bundle must never be able to understate what happened.**

That is stronger than "the bundle must be accurate", and the difference drives
most of the design. A bundle that is missing records while looking complete is
worse than one that admits a gap, because the first is read as exoneration. So
the architecture is biased in one direction throughout: when a layer cannot
record, it refuses to act; when a check cannot be made, the bundle says so
rather than staying quiet; and when two readings are possible, the weaker one
is recorded.

The corollary is less obvious and was the subject of the third review: a
verifier that only reads records which volunteer information makes **absence
indistinguishable from compliance**, which inverts the claim. The emptiest
bundle must not be the cleanest. See [evidence.md](evidence.md#the-floor).

## One run, end to end

```text
wl-enclave run
   |
   |  1. load and validate enclave.yaml; report EVERY problem before
   |     anything exists                                   config.py
   |
   |  2. create runs/<id>/{evidence,guard,bundle}            runs.py
   |     open the chain, verifying it if one is there     evidence.py
   |     record what governs this run (file digests)       config.py
   |
   |  3. start the egress guard FIRST, so the sandbox has
   |     somewhere to be pointed at                 egress/local.py
   |         +-- internal docker network, no route out
   |         +-- guard joins it AND an egress network
   |         +-- wait for the guard's own "listening on"
   |
   |  4. build the sandbox spec and provision it      drivers/docker.py
   |         +-- coherence checked on the spec, not in the driver
   |         +-- read the constraints back OUT of the runtime
   |         +-- confirm the evidence mask by reading a planted canary
   |
   |  5. the agent runs. two independent record streams:
   |         decisions  -> runs/<id>/evidence/   (agent-authored)
   |         egress     -> runs/<id>/guard/      (guard-authored)
   |
   |  6. drain the guard so it writes its closing account
   |     ingest both streams into the chain, with an account of
   |     anything dropped at the boundary
   |     reconcile the tallies against the chain itself
   |     seal                                            evidence.py
   v
runs/<id>/bundle/{chain.jsonl,manifest.json}
   |
   +-- wl-enclave verify, offline, no account, no network
```

Step 3 before step 4 is deliberate: a sandbox that starts before its guard has
a window with no witness.

## Two layers that cannot answer for each other

Watchlight knows the agent asked to wire money and not that it tried to reach
an unlisted host. The guard knows the reverse. Neither can be derived from the
other, which is why a bundle holds both and why the attestation says, per
control, how strongly each was established.

## What is not built yet

Stated here because a design document that reads as a description of a finished
system is misleading.

- **Bundles are unsigned.** The chain proves internal consistency, not origin,
  and hash chaining does not stop truncation. Tracked in issues #2–#6.
- **Traffic blocked by topology is not recorded.** A raw socket to an arbitrary
  port has no route out, so the guard never sees it. The bundle says this about
  itself rather than leaving it to be discovered. Tracked in #12.
- **The workspace is writable**, so a run can edit the rules its successor is
  held to. Made visible by digests rather than prevented. Tracked in #13.
