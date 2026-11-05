# Evidence

## The chain

`bundle/chain.jsonl` is append-only, one JSON record per line. Each record
carries `seq`, `ts`, `type`, `data`, `prev` and `hash`, where `hash` is over
all of the preceding fields including `prev`. Editing any record breaks every
hash after it.

`bundle/manifest.json` is written at seal and carries the head hash and the
record count.

Two properties worth being precise about, because the difference between them
is the whole case for signing:

- **Editing is detected.** Change a record and its own hash no longer matches
  its content.
- **Truncation is not.** Drop records off the end and what remains is a
  shorter, perfectly valid chain. Nothing *in* the chain says how long it
  should have been. `manifest.json` does — which is exactly why the manifest is
  the thing worth signing, and why an unsigned manifest is a weak defence,
  since whoever truncates can rewrite it to match.

A chain is **verified before it is extended**. Resuming from the head of a
chain nobody checked is how tampering becomes self-consistent: append onto an
edited record and seal, and every hash from the edit onward is recomputed to
agree with it — the one operation that would have caught the edit is the one
that overwrites the evidence of it.

Containment never waits on that check. `wl-enclave kill` stops the sandbox
*before* opening the chain, because an operator reaching for kill wants the
agent stopped whether or not its evidence is intact, and making containment
depend on a successful read would hand an agent that corrupted its own bundle
a way to stay running.

## Four verdicts

`verify` reports the worst of three independent claims. They are not degrees of
one thing, and collapsing them would make the output worthless — a reviewer who
learns that one bad word covers everything stops reading the word.

| Verdict | Exit | Means |
|---|---|---|
| `OK` | 0 | the chain verifies, every control held, nothing is known to be missing |
| `INCOMPLETE` | 1 | everything stated is true, and some of what happened is not here |
| `UNCONTAINED` | 1 | the chain verifies and reports that **isolation** did not hold |
| `FAILED` | 1 | the chain does not verify — edited, reordered, truncated |

Ordered by what each costs a reader. `FAILED` comes first because nothing else
in the bundle can be relied on once it holds. `UNCONTAINED` is **not** a weaker
`FAILED`: `FAILED` says *do not trust this file*, `UNCONTAINED` says *trust
this file and act on what it says*. Reporting a sandbox whose isolation slipped
as `FAILED` would tell a reviewer the opposite of the truth.

Only `ok` exits 0, so a CI gate can branch on the exit code alone.

`VerifyResult.ok` means **chain intact and only that**, which is why
`chain_intact` exists as a name for it. Call sites branch on `verdict`.

## The floor

Everything above describes reading records that volunteered something. On its
own that makes **absence indistinguishable from compliance**, which inverts the
product claim: the emptiest bundle would be the cleanest. So `verify` also asks
whether the records that must exist do exist.

- **A run ends exactly once, and says so** — one of `run.close`,
  `run.contained`, `run.error`. None is a `FAILED`-class problem, because a
  chain with no end is indistinguishable from one truncated. More than one
  means something else wrote a record.
- **`run.error` is `incomplete` at best.** A run that failed before it was
  under way never attested anything, and the absence of those records is not
  evidence of a clean run. Without this, the worst runs produced the shortest,
  cleanest bundles.
- **A guard that was started owes an attestation.** No attestation is
  `incomplete`; an attestation reporting `route_exclusive: false` is a
  `problem`, because the egress records are then a lower bound rather than an
  account.
- **`run.close`'s tallies are reconciled against the chain.** The bundle counts
  what it ingested and stores those counts beside the records, which is the one
  internal cross-check the format has. A disagreement is a `problem` rather
  than an incompleteness: the bundle is not reporting a gap it knows about, it
  is making two statements that cannot both be true.
- **A control name outside the shared vocabulary is reported**, not sorted into
  a claim by guesswork. A name this verifier does not know means a writer and
  the verifier have drifted, which is the failure the closed set exists to
  prevent.

## Record vocabulary

Host-written:

| Type | Says |
|---|---|
| `run.open` | run id, agent, purpose, runtime, command, version |
| `config.attested` | digests of `enclave.yaml` and every policy file that governed this run |
| `sandbox.attested` | constraints read back out of the runtime, plus named controls |
| `egress.guard_started` | which guard, which endpoint, which network |
| `egress.attested` | whether the runtime confirms the guard was the only route, and what the records cover |
| `egress.guard_stopped` | the guard was not running at the end of the run |
| `decision` | one authorization decision, stamped `asserted_by: sandbox` |
| `decision.ingest` | what was dropped, truncated or malformed at the decision boundary |
| `run.close` / `run.contained` / `run.error` | how the run ended, with tallies |

Guard-written, ingested into the chain against a closed set of permitted types:

| Type | Says |
|---|---|
| `egress.attempt` | host, port, verdict, reason, protocol, and `resolved_ip` when an address was chosen |
| `egress.malformed` | a request that could not be parsed — refused, and still counted |
| `egress.tunnel` | bytes each way, duration, outcome |
| `egress.tunnel_progress` | volume on a tunnel that is still open |
| `egress.saturated` | connections refused at capacity, with no destination read |
| `egress.records_suppressed` | the guard's own account of records it could not write |

A record whose declared type is not in the permitted set is **kept**, as
`egress.unrecognised` carrying the original, rather than dropped — an unrecognised record is itself worth
seeing, and dropping it would let a writer erase evidence by malforming it.

## Why dropped records are `incomplete` and not `failed`

A rate-limited run and a tampered one must not read alike. Collapsing them is
how a reviewer learns to ignore both. So anything the bundle says about its own
gaps — suppressed records, write failures, a guard that stopped early, a
control that could not be confirmed, a rule file that could not be read — lands
on `incomplete`, and only chain integrity lands on `failed`.
