# Evidence: what a bundle proves

A bundle is two files:

```text
bundle/chain.jsonl     one JSON record per line, append-only
bundle/manifest.json   written when the run is sealed
```

Here's a real record — the agent tried to reach pastebin.com, which wasn't on
the allowlist:

```json
{
  "seq": 9,
  "ts": "2026-11-05T01:06:16.540177+00:00",
  "type": "egress.attempt",
  "data": {
    "event": "egress.attempt",
    "host": "pastebin.com",
    "port": 443,
    "protocol": "connect",
    "verdict": "deny",
    "reason": "pastebin.com:443 is not in the allowlist",
    "ts": "2026-11-05T01:06:16.317050+00:00"
  },
  "prev": "5d14a325b148e3d19e8be79d112a6e0c14ce9b2e5401f0b0dc5d7c9f69f813ca",
  "hash": "9d8824737848d29d17e4f44b0c78cb64128dbc286f89f022a4b7067682fcf351"
}
```

`hash` covers everything above it *including* `prev`. So each record is
cryptographically tied to the one before it, and the manifest pins the last one:

```json
{
  "format": "wl-enclave-evidence/1",
  "run": "20261105-010615-b534ef",
  "head": "3102f569a1d9b4a1d4cfb81044d7da06db9d33651c2f6aed123ad06e33052cba",
  "records": 11,
  "exit_status": 0,
  "sealed_at": "2026-11-05T01:06:16.540307+00:00"
}
```

## Edits are caught. Truncation is not.

This distinction matters more than anything else on this page, so let's be
concrete.

**Change a record** → its hash no longer matches its content, and every hash
after it breaks too. `verify` reports `FAILED`. This works.

**Delete the last three records** → what's left is a shorter chain where every
hash still checks out perfectly. Nothing *inside* the chain knows how long it
should have been.

The manifest knows — `records: 11` — which is exactly why the manifest is the
thing we sign. An Ed25519 signature covers the manifest body, so whoever
truncates the chain can no longer just edit the count to match: without the key
they cannot produce a manifest that verifies.

**With the key, they still can**, and that is worth being blunt about because
it is the part people assume signing fixed. The key holder truncates the chain,
appends a `run.close` whose counts agree with what's left, re-seals, and the
bundle verifies as `ok` against a pinned key — with a denial simply gone. There
is a test that performs that forgery and asserts it succeeds, so nobody can
quietly upgrade the claim:

```
test_a_key_holder_can_still_reseal_a_truncated_chain
```

Why we shipped it anyway: it moves the attacker from *anyone who can write the
file* to *whoever holds the key*, which is a much smaller set and one you can
put in an HSM. What it does not do is make a bundle evidence against its own
operator. For that, the signature has to come from somewhere the operator
can't reach — a cosignature from a witness they don't run. Every manifest
carries an empty `cosignatures` list for exactly that, and the verifier already
checks entries in it, so adding a witness later needs no format change and no
verifier change. That work is issues #2–#6; #5 covers checkpoint signatures
during a run, which is what would bound how much can be cut off the end.

So, precisely: a signature here means *this is the bundle that key sealed, and
nothing has changed since*. It does not mean *this is everything that
happened*. `verify` prints `unsigned`, `self-signed` or `signed by the expected
key` to keep those apart, and only the third says anything about who.

## Verify before you extend

When we resume from an existing chain, we verify it first. This sounds like
politeness; it's load-bearing.

Picture an attacker who edits record 4. The edit is detectable — record 4's
hash doesn't match. But if we then append record 12 onto the chain without
checking, we recompute hashes forward from the current head, and now records 4
through 12 all agree with each other. **The one operation that would have
caught the edit is the operation that destroys the evidence of it.**

One exception: `wl-enclave kill` stops the sandbox *before* opening the chain.
If you're reaching for kill, you want the agent stopped whether or not its
evidence is intact. Making containment depend on a successful read would hand
an agent that corrupted its own bundle a way to keep running.

## The four verdicts

```text
$ wl-enclave verify runs/20261105-010615-b534ef/bundle
wl-enclave: controls 11/11 in force
wl-enclave: governed by sha256:c63334f542a4b405f6f8099cc7889c801d0b5969c5d4cfd0359915d15c5e627f
wl-enclave: OK — 11 records, chain intact, signed by the expected key
```

| Verdict | Exit | What it means |
|---|---|---|
| `OK` | 0 | chain verifies, every control held, nothing known to be missing |
| `INCOMPLETE` | 1 | everything here is true, and some of what happened isn't here |
| `UNCONTAINED` | 1 | chain verifies, and it says isolation didn't hold |
| `FAILED` | 1 | the bundle can't be taken at face value — the chain doesn't verify, or it contradicts itself |

Only `OK` exits 0, so CI can just check the exit code.

**Why `UNCONTAINED` isn't just a milder `FAILED`:** they tell you opposite
things. `FAILED` means *don't trust this file*. `UNCONTAINED` means *trust this
file, and act on what it says*. If we reported a sandbox whose isolation
slipped as `FAILED`, we'd be telling you to disregard the very record you need
to act on.

We considered collapsing these into one "bad" state. Don't: the moment one word
covers everything, people stop reading the word.

One naming note — `VerifyResult.ok` means "the chain is intact" and nothing
more. There's a `chain_intact` property that says so plainly. Everything else
branches on `verdict`.

## The floor

Everything so far is about reading records that *told* us something. On its own
that's a trap: a bundle with no records at all would sail through.

So `verify` also checks that records which *must* exist do exist.

**A run ends exactly once, and being stopped is not the same as ending.**
`run.close` and `run.error` end a run: at most one, and it is the last record,
because anything after it describes a run that had already finished. Zero
endings *and* no `run.contained` is `FAILED` — a chain with no ending at all is
indistinguishable from one that got truncated.

`run.contained` says the run was **stopped**, by its timeout or by an operator
reaching for `kill`. It is not an ending, because a stopped run still closes:
the timeout path contains the sandbox and then seals with `run.close` and its
tallies, having genuinely done both. It may be the last record, when whatever
would have closed the chain never got to.

Treating all three as endings and counting them was wrong in both directions. A
killed run whose chain ended at `run.contained` counted as one clean ending and
verified `OK`, the same verdict as a run that completed — a bundle understating
what happened. A timed-out run counted as two and returned `FAILED` on evidence
that was sound, so an operator could not tell a properly contained run from a
broken bundle, because both exited 1.

**`run.contained` caps out at `INCOMPLETE`.** Whatever the agent had not done
when it was stopped is absent from the bundle, and absent is not clean. The
reason says which kind of stop, so an operator reading the verdict knows
whether a limit fired or a person intervened.

**`run.error` caps out at `INCOMPLETE`.** A run that died during startup never
attested anything, and the absence of those records is not evidence of a clean
run. Before this check, our worst runs produced our shortest, cleanest bundles.

**A guard that started owes us an attestation.** Missing → `INCOMPLETE`. An
attestation saying `route_exclusive: false` → a problem, because the egress
records are then a lower bound rather than a complete account.

**`run.close` tallies get cross-checked.** The close record says "7 decisions,
2 egress attempts"; we count what's actually in the chain. A mismatch is a
*problem*, not an incompleteness — the bundle isn't reporting a gap it knows
about, it's making two statements that can't both be true.

**The rule files get read twice.** They're also sealed read-only where the
workspace exposes them, which is the primary defence and is described in
[the sandbox](./sandbox.md). Reading them twice is what remains useful once
writes are refused: it's how a bundle shows the seal actually held, rather than
asking a reader to trust that it was configured. If a mount is ever
misconfigured, the two readings are what notice.

So `config.attested` is what governed the start and `config.reattested` is what
governed the end. Two readings that disagree are a *problem*, for the same
reason a tally mismatch is: nothing's missing, and the bundle is making two
statements about what the run was allowed to do that can't both be true. The
report names the files, and whether each was rewritten, added or removed —
being handed a new rule and rewriting an existing one are different events, and
a combined digest can't tell them apart.

`governed_by` stays the *opening* digest. It's what a gate pins to assert a run
was governed by rules it recognises, and pointing it at the closing reading
would let a run that rewrote its rules mid-flight satisfy a pin it never
actually ran under.

The reason this is a separate record type rather than a second
`config.attested` is older verifiers. They skip a type they don't know, so they
keep reporting the opening digest. Reuse the existing type and they'd read the
*last* one instead — handing back the digest of the rules the agent rewrote, as
the authoritative answer to what governed the run.

The limit worth stating: two readings compare two points, not the interval
between them. An agent that edits a rule file, acts under it and puts the
original back leaves two digests that agree. Catching that needs a watch on the
files, which is a different mechanism.

**Unknown control names get reported.** If a writer emits a control name this
verifier doesn't recognise, we say so rather than guessing which category it
belongs in. An unrecognised name means the writer and verifier have drifted
apart, which is the exact failure the shared vocabulary exists to prevent.

## The records

Written by the host:

| Type | Contents |
|---|---|
| `run.open` | run id, agent, purpose, runtime, command, version |
| `config.attested` | digests of `enclave.yaml` and every policy file in play, at the start |
| `config.reattested` | the same files read again at the end, to show whether they moved |
| `sandbox.attested` | constraints read back out of Docker, plus named controls |
| `egress.guard_started` | which guard, which endpoint, which network |
| `egress.attested` | was the guard the only route, and what do the records cover |
| `egress.guard_stopped` | the guard wasn't running when the run ended |
| `decision` | one authorization decision, stamped `asserted_by: sandbox` |
| `decision.ingest` | what got dropped, truncated, or rejected at the boundary |
| `run.close` / `run.error` | how it ended, with tallies |
| `run.contained` | that it was stopped, and why — not an ending |

Written by the guard, accepted only against a closed set of types:

| Type | Contents |
|---|---|
| `egress.attempt` | host, port, verdict, reason, protocol, resolved IP |
| `egress.malformed` | a request we couldn't parse — refused, and still counted |
| `egress.tunnel` | bytes each way, duration, outcome |
| `egress.tunnel_progress` | volume on a tunnel that's still open |
| `egress.saturated` | connections refused at capacity |
| `egress.records_suppressed` | the guard's own account of records it couldn't write |

A guard record with a type outside that set isn't dropped — it's kept as
`egress.unrecognised` with the original inside. An unexpected record is itself
worth seeing, and dropping it would let a writer erase evidence just by
malforming it.

## Why dropped records are `INCOMPLETE`, not `FAILED`

A rate-limited run and a tampered run must not look the same. If they did,
people would learn to shrug at both.

So anything the bundle says about *its own* gaps — suppressed records, write
failures, a guard that died early, a control we couldn't confirm, a policy file
we couldn't read — lands on `INCOMPLETE`. Only chain integrity lands on
`FAILED`.
