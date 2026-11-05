# Attestation: naming the controls

We used to collapse each layer's enforcement into one boolean. The guard
reported `route_exclusive: true`, the sandbox reported a handful of settings.

That's enough to say a layer held. It's not enough to say *what* held — and
`route_exclusive` is really four facts ANDed together, so a `false` doesn't
tell you which one broke. When someone asks why a bundle is weaker than they
expected, they're always asking about one specific control.

So every control is named, and each one tells you three things:

```json
"evidence_masked_from_sandbox": {
  "in_force": true,
  "verified_by": "runtime_readback",
  "detail": "a tmpfs is mounted at every declared path in the sandbox's own
             mount table; a canary planted behind each one was unreadable from
             inside, and an unmasked canary was readable in the same probe round"
}
```

## 1. Did it hold?

| `in_force` | Reading |
|---|---|
| `true` | yes. The normal case; contributes nothing to the verdict |
| `false` | no |
| `null` | we couldn't tell. It may well have held — we can't say |

`null` lands on `INCOMPLETE`, which already means "everything stated is true,
something is unknown" — same verdict a dropped record gets, for the same
reason.

## 2. How do we know?

This is the distinction the module exists for. A control we read back out of
the runtime and a control we merely *asked for* are both "configured", and in a
bundle they're indistinguishable unless the record says which.

| `verified_by` | Establishes? | Means |
|---|---|---|
| `runtime_readback` | yes | read out of the running system |
| `network_topology` | yes | true by construction — there's no route to read back because none was ever created |
| `runtime_config_readback` | yes | Docker's record of what the container was asked for. Not our own argv echoed back, so it catches a setting that never reached the daemon — but not the kernel's view of what's in force |
| `requested_not_readback` | **no** | we asked. We never checked |

That last row is **enforced, not just documented**. A control resting on
`requested_not_readback` is reported as unverified no matter what its
`in_force` says.

Why bother? Because without it, a driver could fill every control with
`control(True, REQUESTED)` — literally copying its own spec back out, which the
driver protocol forbids but nothing prevented — and produce a bundle that was
byte-identical in verdict to a genuinely verified run. We tested this; it
worked. Now it comes out `INCOMPLETE`.

A provenance string this build doesn't recognise also fails to establish
anything, so a driver can't invent a stronger-sounding label.

## 3. Which claim does it bear on?

`in_force: false` used to mean two unrelated things, and both routed to
`UNCONTAINED`:

- **containment** failed — the sandbox was less isolated than intended
- **witnessing** failed — the run was less *observed* than intended

These move independently, and sometimes in opposite directions. Concretely: the
guard dies on an internal network. The sandbox can now reach *nothing at all*.
The run is strictly **more** contained and strictly **less** witnessed.

Reporting that as `UNCONTAINED` sends you hunting for an escaped agent when
what actually happened is that the witness died. Worse, it spends the one alarm
that should only ever mean "isolation failed".

| Containment | Witnessing |
|---|---|
| `network_unroutable` | `guard_attached` |
| `sandbox_single_network` | `guard_has_egress` |
| `sandbox_on_intended_network` | `guard_live_at_readback` |
| `rootfs_read_only` | |
| `capabilities_dropped` | |
| `no_new_privileges` | |
| `runs_as_non_root` | |
| `evidence_masked_from_sandbox` | |

A false containment control → `UNCONTAINED`. A false witnessing control →
`INCOMPLETE`, with its own named reason.

*(I had this wrong for a while and defended it. The tell was one of my own
tests: `test_a_guard_that_stopped_early_makes_the_bundle_incomplete` was
asserting `verdict == "uncontained"`. I'd changed the assertion and kept the
name, then written a comment explaining the mismatch rather than listening to
it.)*

## Merging: weakest wins

A run has several attesting moments. The network topology is read when the
sandbox is provisioned; the guard's fate isn't known until the end. So controls
from different layers get folded together, and the fold takes the **weakest**
claim.

Two reasons, and both matter:

**It's safe.** Taking the *latest* would let anyone who can append a record
overwrite a finding with a flattering one. Weakest-wins can only be abused in
the direction that makes the bundle describe a *worse* run than really
happened — the one direction that doesn't mislead anybody.

**It's also just correct.** `guard_live_at_readback` was genuinely true when we
read the topology and genuinely false by the end. The second fact is the one
that bears on the evidence.

Both axes rank. We originally ranked on `in_force` alone, which meant that when
two layers agreed on the state, the first record's provenance won regardless of
strength — so a control read out of the runtime could be silently downgraded to
one we'd merely asked for, with nothing visible changing.

## The strongest claim in a bundle

`evidence_masked_from_sandbox` at `runtime_readback`, because it's confirmed by
*effect* rather than configuration: a file planted behind the mask couldn't be
read from inside, a tmpfs appears at the declared path in the sandbox's own
mount table, and a file at an unmasked path *was* readable in the same round.

The last clause is doing real work — see
[trust-boundaries.md](trust-boundaries.md#the-mask) for how we found that out.
