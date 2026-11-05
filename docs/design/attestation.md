# Attestation

An attestation used to collapse a layer's enforcement into one boolean. That is
enough to say a layer held and not enough to say *what* held — and
`route_exclusive` in particular is a conjunction of four facts, so a false
answer does not say which term failed. A reviewer asking why a bundle is weaker
than expected is always asking about one specific control.

So each control is **named**, and each says three things.

```json
"evidence_masked_from_sandbox": {
  "in_force": true,
  "verified_by": "runtime_readback",
  "detail": "a tmpfs is mounted at every declared path in the sandbox's own
             mount table; a canary planted behind each one was unreadable from
             inside, and an unmasked canary was readable in the same probe round"
}
```

## 1. Whether it was in force

| `in_force` | Reading |
|---|---|
| `true` | established. The normal case; contributes nothing to the verdict |
| `false` | the control did not hold |
| `null` | could not be determined. It may well have held; we cannot say |

`null` lands on `incomplete`, which already means "everything stated is true
and something is unknown" — the same verdict a dropped record produces, for the
same reason.

## 2. How that was established

The distinction the module exists for: a control read back out of the runtime
and a control we merely asked for are both "configured", and in a bundle they
are indistinguishable unless the record says which.

| `verified_by` | Strength | Means |
|---|---|---|
| `runtime_readback` | establishes | read out of the running system |
| `network_topology` | establishes | true by construction; there is no route to read back because none was created |
| `runtime_config_readback` | establishes | the runtime's record of what the container was asked for. Not our own argv echoed back, so it catches a setting that never reached the daemon — but not the kernel's account of what is in force |
| `requested_not_readback` | **does not establish** | asked for, never confirmed |

`requested_not_readback` does not establish anything, and this is **enforced**,
not just documented: a control resting on it is reported as unverified whatever
its `in_force` says. Without that, a driver could fill every control with
`control(True, REQUESTED)` — copying its own spec back out, which the driver
protocol explicitly forbids — and produce a bundle byte-identical in verdict to
a genuinely read-back run. A provenance string this build does not recognise
also fails to establish, so a driver cannot invent a stronger-sounding label.

## 3. Which claim it bears on

`in_force: false` meant two unrelated things, and both routed to `UNCONTAINED`:

- **containment** failed — the sandbox was less isolated than intended;
- **witnessing** failed — the run was less *observed* than intended.

Those move independently, and sometimes in opposite directions. A guard that
dies on an internal network leaves the sandbox able to reach nothing at all:
the run is strictly **more** contained and strictly **less** witnessed.
Reporting that as `UNCONTAINED` sends an operator looking for an escaped agent
when the truth is that the witness died — and it spends the one alarm that
should mean isolation failed.

| Containment | Witnessing |
|---|---|
| `network_unroutable` | `guard_attached` |
| `sandbox_single_network` | `guard_has_egress` |
| `sandbox_on_intended_network` | `guard_live_at_readback` |
| `rootfs_read_only` | |
| `capabilities_dropped` | |
| `no_new_privileges` | |
| `evidence_masked_from_sandbox` | |

A false containment control reads `UNCONTAINED`. A false witnessing control
reads `INCOMPLETE`, with its own named reason.

## Merging: weakest wins, on both axes

A run has more than one attesting moment — the topology is read when the
sandbox is provisioned, and the guard's fate is known only at the end — so
controls from several layers are folded together. The fold takes the **weakest**
claim, which is both safe and correct:

- **Safe**, because taking the latest would let anything able to append a
  record overwrite a finding with a flattering one. Weakest-wins can only be
  abused in the direction that makes the bundle describe a *worse* run than
  happened, which is the one direction that does not mislead.
- **Correct**, because `guard_live_at_readback` was genuinely true when the
  topology was read and genuinely false by the end, and the second fact is the
  one that bears on the evidence.

Both axes rank. Ranking on `in_force` alone meant that when two layers agreed
on a state, the first record's provenance won regardless of strength — so a
control read out of the runtime could be silently replaced by one merely asked
for.

## The strongest claim this makes, and its edge

`evidence_masked_from_sandbox` at `runtime_readback` is the strongest claim in
a bundle, because it is confirmed by effect rather than configuration: a file
planted on the host behind the mask could not be read from inside, a tmpfs
appears at the declared path in the sandbox's own mount table, and a file at an
unmasked path *was* readable in the same probe round.

That last clause is load-bearing. Without it, every probe failing — a container
that had exited, an exec that was refused, an image with no `cat` — read as
"the canary was unreadable, therefore the mask holds", and the control returned
`true` with the strongest provenance label in the vocabulary from no
observation at all. Exit codes are distinguished for the same reason: `cat`
exits 1 for a file it cannot find, and 126/127 when exec itself failed, which
says nothing about the file.
