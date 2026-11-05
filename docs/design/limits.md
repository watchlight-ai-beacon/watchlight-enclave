# Limits

Every bound, with what it prevents. A limit whose reasoning is not written down
gets raised by whoever next finds it inconvenient.

## Guard record budget

| Constant | Value | Prevents |
|---|---|---|
| `MAX_RECORDS` | 10 000 per run | an unbounded evidence file |
| `MAX_PER_SECOND` | 50 | a burst filling the file faster than anyone can read it |
| `MAX_SATURATION_NOTES` | 120 | see below |

Saturation notes have their **own** allowance, and this is the single most
important thing on this page. When they shared the record budget, a flood of
payload-free connects — the cheapest thing an agent can do — filled the file,
after which a real tunnel to an allowlisted host went unrecorded while the
bundle still read "attested, no attempts". Cheap noise must never be able to
spend the budget that expensive evidence needs.

Notes are aggregated at most once per second and carry
`refused_since_last_note` and `refused_total`, so the count survives the
aggregation.

When the budget is exhausted the guard **refuses connections** rather than
forwarding unrecorded ones. The bundle then reads `INCOMPLETE` and states the
size of its own gap.

## Connection bounds

| Constant | Value | Reasoning |
|---|---|---|
| `MAX_CONNECTIONS` | 256 | concurrency ceiling |
| `MAX_REFUSALS_IN_FLIGHT` | 64 | past this, refusals are dropped without a permit, so refusing cannot itself be the exhaustion |
| `MAX_HEAD_BYTES` | 8 KiB | a request head is not a payload |
| `HEAD_TIMEOUT` | 10 s | a connection that opens and says nothing |
| `CONNECT_TIMEOUT` | 10 s | dialling upstream |
| `TUNNEL_MAX_LIFETIME` | 1 h | an upper bound on one connection |
| `TUNNEL_PROGRESS_INTERVAL` | 5 min | bounds what a run killed mid-transfer fails to record |
| `MAX_TUNNEL_PROGRESS` | 12 | a budget spent on one connection's progress is unavailable to the next connection's attempt, and an attempt is the more important record |

There is **no idle-read timeout** on an established tunnel, so an open idle
connection holds a permit for up to an hour. Because the guard fails closed,
the consequence is denial of service against the agent rather than a hole in
the evidence — the right direction, but still worth bounding. Tracked in #8.

## Decision ingest

| Constant | Value | Prevents |
|---|---|---|
| `MAX_DECISIONS` | 10 000 | a loop burying the records a reviewer came for |
| `MAX_FIELD_CHARS` | 512 | an unbounded field is an unbounded chain |

Decisions are agent-authored, so these are applied at the boundary along with
field allowlisting, control-character scrubbing and a provenance stamp. What
was dropped is recorded in `decision.ingest` — a limit that hides its own
effect is the problem rather than the control.

## Guard startup

| Constant | Value | Reasoning |
|---|---|---|
| `GUARD_START_TIMEOUT` | 15 s | the guard must be serving before the sandbox exists |
| `GUARD_READY_MARKER` | `listening on` | the guard's own statement that it is ready |

Readiness is the guard's own log line, not a probe. An earlier version probed
with `/dev/tcp`, which is a bash-ism — the guard image has `dash`, so a healthy
guard was reported dead. A liveness check that produces false negatives is
worse than none, because it fails the run for a working system.
