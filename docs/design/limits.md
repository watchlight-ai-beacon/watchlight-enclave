# Limits

Every bound, with what it prevents. Written down because a limit whose
reasoning isn't recorded gets raised by whoever next finds it inconvenient.

## Guard record budget

| Constant | Value | Prevents |
|---|---|---|
| `MAX_RECORDS` | 10,000 per run | an unbounded evidence file |
| `MAX_PER_SECOND` | 50 | a burst filling the file faster than anyone can read it |
| `MAX_SATURATION_NOTES` | 120 | see below |

**Saturation notes have their own allowance, and this is the most important
line on this page.**

When they shared the main record budget, here was the attack: flood the guard
with payload-free connections — the cheapest thing an agent can do — until the
file is full. Then open a real tunnel to an allowlisted host. It goes
unrecorded, and the bundle still reads "attested, no attempts".

Cheap noise must never be able to spend the budget that expensive evidence
needs.

Notes are aggregated at most once per second and carry
`refused_since_last_note` and `refused_total`, so the count survives the
aggregation.

When the budget runs out the guard **refuses connections** rather than
forwarding unrecorded ones. The bundle then reads `INCOMPLETE` and states the
size of its own gap.

## Connection bounds

| Constant | Value | Reasoning |
|---|---|---|
| `MAX_CONNECTIONS` | 256 | concurrency ceiling |
| `MAX_REFUSALS_IN_FLIGHT` | 64 | past this, refusals are dropped without taking a permit — so refusing can't itself become the exhaustion |
| `MAX_HEAD_BYTES` | 8 KiB | a request head is not a payload |
| `HEAD_TIMEOUT` | 10 s | a connection that opens and says nothing |
| `CONNECT_TIMEOUT` | 10 s | dialling upstream |
| `TUNNEL_MAX_LIFETIME` | 1 h | upper bound on a single connection |
| `TUNNEL_PROGRESS_INTERVAL` | 5 min | bounds what a run killed mid-transfer fails to record |
| `MAX_TUNNEL_PROGRESS` | 12 | budget spent on one connection's progress isn't available for the next connection's *attempt* — and an attempt is the more important record |

**There's no idle-read timeout** on an established tunnel, so an open idle
connection can hold a permit for up to an hour. Because the guard fails closed,
the consequence is denial of service against the agent rather than a hole in
the evidence — the right direction, but still worth fixing. Issue #8.

## Decision ingest

| Constant | Value | Prevents |
|---|---|---|
| `MAX_DECISIONS` | 10,000 | a loop burying the records you came for |
| `MAX_FIELD_CHARS` | 512 | an unbounded field is an unbounded chain |

These are agent-authored records, so the limits are applied at the boundary
along with field allowlisting, control-character scrubbing, and a provenance
stamp — see
[trust-boundaries.md](trust-boundaries.md#records-the-agent-writes-which-we-dont-trust).

Whatever got dropped is recorded in `decision.ingest`. A limit that hides its
own effect is the problem rather than the control.

## Guard startup

| Constant | Value | Reasoning |
|---|---|---|
| `GUARD_START_TIMEOUT` | 15 s | the guard has to be serving before the sandbox exists |
| `GUARD_READY_MARKER` | `listening on` | the guard's own statement that it's ready |

Readiness is the guard's log line, not a probe. We originally probed with
`/dev/tcp`, which is a bash-ism — and the guard image has `dash`, so a
perfectly healthy guard was reported dead. A liveness check that produces false
negatives is worse than no check, because it fails the run for a working
system.
