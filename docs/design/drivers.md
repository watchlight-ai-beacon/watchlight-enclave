# Drivers

A driver isolates the agent. `RuntimeDriver` is the seam; `runtime:` in
`enclave.yaml` picks one.

```python
name: str
def preflight(self) -> list[str]        # problems, never raises
def provision(self, spec) -> Sandbox
def attest(self, sandbox) -> dict       # read BACK from the runtime
def wait(self, sandbox, timeout) -> Optional[int]
def logs(self, sandbox) -> str
def quarantine(self, sandbox) -> None   # kill now, do not cooperate
def teardown(self, sandbox) -> None
```

## The failure mode that matters most

**Could a second driver satisfy this protocol while producing materially weaker
evidence, with nothing failing?** That question is worth more than any other
when reviewing this seam, because a driver that silently attests less is
indistinguishable, in a bundle, from one that attests honestly.

Three defences, each added because the answer was once yes:

1. **`requested_not_readback` does not establish a control.** A driver that
   copies its own `SandboxSpec` back out — which `attest()` explicitly forbids
   — produces `incomplete`, not `ok`. Previously it produced a bundle
   byte-identical in verdict to a genuine readback.
2. **A control name outside the shared vocabulary is reported.** A driver
   inventing names does not get them quietly counted.
3. **Spec coherence is enforced on the spec, not in a driver.** The nesting
   invariant between masks and binds lived inside the Docker driver, which
   meant a second driver had to reimplement it or silently omit it — and
   omitting it is invisible, because a runtime reports a mask as requested
   whether or not it covers anything.

Still open: `attest()` returns an untyped `dict`, so "which controls did you
answer" is a reading-comprehension exercise rather than a type error. A missing
`constraints` key raises; a missing `controls` key is silent. Those failure
modes are inverted — noisy for the cosmetic key, silent for the evidentiary
one.

## What a spec carries

`SandboxSpec` is driver-neutral by construction, and holds behaviour rather
than just values.

**Mounts** are one ordered list covering both binds and masks, discriminated by
`source is None`. They were two lists, and that cost twice over: the
relationship between them was validated inside one driver, and the caller had
to derive a masked path from a mount target it held separately — which is how a
mask could name somewhere no mount reached. `Mount.bind()` and `Mount.mask()`
are the constructors, so a mask with a source is not a thing that can be
written.

Coherence is checked in `__post_init__`, and also available as
`incoherent_mounts()` so a caller can report every problem at once the way
`config.load` does rather than raising on the first.

**Egress** is an intent, not a network name. `"none"` and
`"wl-enclave-<run>-int"` are both just strings, and nothing in a string says
whether a named network is internal with a guard as its only route or an
ordinary bridge with a default route to the internet. `Egress` carries the
network, whether the route is guard-mediated, the endpoint, and the allowlist —
the allowlist travels with it because a bundle stating the topology without the
policy describes half a boundary.

That turns the attestation from a report into a check: the driver compares the
networks actually attached against the one its spec asked for. "One network,
named X" and "the network asked for, and nothing else" are different claims,
and only the second catches a sandbox that came up somewhere else because a
network creation failed and something fell back.

Two combinations are refused where they are written: egress claiming mediation
while naming no network, and egress naming an endpoint without claiming
mediation. The second is the interesting one — a sandbox merely *pointed* at a
guard it is not required to go through looks identical, in a bundle, to one
whose only route is that guard.

## What the Docker driver actually does

- one internal network per run, no route out; the guard bridges it to an egress
  network
- read-only rootfs, all capabilities dropped, `no-new-privileges`, memory, CPU
  and PID ceilings
- tmpfs over `/work/runs`, confirmed by canary readback rather than by the
  daemon's record of the request
- constraints read back out of `docker inspect`, never echoed from the spec

`podman` uses the same driver, selected by binary name.

## Adding a driver

A new driver's real work is not the seven methods — it is deciding, for each
control in the shared vocabulary, whether it can honestly claim the control and
at what `verified_by` level. A driver whose isolation differs should attest
*different* controls, not the same ones more weakly.

A runtime that shares no filesystem with the guest, for instance, does not need
the mask machinery at all: there is no host directory to hide, so
`evidence_masked_from_sandbox` is in force by construction rather than by
canary. That is a stronger claim arrived at by a different route, and the
vocabulary is designed to say so.

Where a driver's enforcement point sees more traffic than a CONNECT proxy does,
`records_cover` and `blocked_not_recorded` are how the bundle says so — and
those fields are the reason a driver with better coverage does not need the
verdict logic changed to benefit from it. `Egress` will need to carry the
mediation *mechanism* rather than a boolean for that to work cleanly; see
[egress.md](egress.md#what-the-records-cover-and-what-they-cannot) and #12.
