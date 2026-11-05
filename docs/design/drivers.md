# Drivers

A driver isolates the agent. `RuntimeDriver` is the seam, and `runtime:` in
your `enclave.yaml` picks one.

```python
name: str
def preflight(self) -> list[str]        # problems, never raises
def provision(self, spec) -> Sandbox
def attest(self, sandbox) -> dict       # read BACK out of the runtime
def wait(self, sandbox, timeout) -> Optional[int]
def logs(self, sandbox) -> str
def quarantine(self, sandbox) -> None   # kill now, don't cooperate
def teardown(self, sandbox) -> None
```

## The question to ask of this seam

> **Could a second driver satisfy this protocol while producing materially
> weaker evidence, with nothing failing?**

That question is worth more than anything else when reviewing driver code,
because a driver that quietly attests less looks — in the bundle — exactly like
one that attests honestly.

Three defences exist because the answer used to be yes:

**1. `requested_not_readback` doesn't establish anything.** A driver that
copies its own `SandboxSpec` back out produces `INCOMPLETE`, not `OK`. It used
to produce a bundle byte-identical in verdict to a genuine readback.

**2. Unknown control names get reported.** A driver inventing names doesn't get
them quietly counted as passes.

**3. Spec coherence is enforced on the spec, not in a driver.** The
mask/bind nesting invariant used to live inside the Docker driver, which meant
a second driver had to reimplement it — or silently skip it. And skipping it is
invisible, because a runtime reports a mask as requested whether or not it
covers anything.

**Still open:** `attest()` returns an untyped `dict`, so "which controls did
you answer?" is a reading-comprehension exercise rather than a type error. A
missing `constraints` key raises `KeyError`; a missing `controls` key is
silent. Those failure modes are exactly backwards — loud for the cosmetic key,
silent for the evidentiary one. Issue #17.

## What a spec carries

`SandboxSpec` is runtime-neutral, and it carries behaviour rather than just
values.

### Mounts

One ordered list covering both binds and masks, discriminated by
`source is None`:

```python
Mount.bind(target="/work", source=project_root)
Mount.mask(target="/work/runs")
```

These used to be two separate lists, which cost us twice: the relationship
between them got validated inside one driver, and callers had to derive a
masked path from a mount target they held separately — which is how a mask
could end up naming somewhere no mount reached.

With the constructors above, "a mask with a source" isn't a thing you can
write.

Coherence is checked in `__post_init__`, and also exposed as
`incoherent_mounts()` so a caller can report every problem at once the way
`config.load` does, rather than raising on the first one.

### Egress

`Egress` is an *intent*, not a network name. And that distinction is the point:
`"none"` and `"wl-enclave-abc123-int"` are both just strings, and nothing in a
string tells you whether a named network is internal with a guard as its only
route, or an ordinary bridge with a default route to the internet.

```python
Egress.mediated_by(network=..., endpoint=..., allow=(...))
Egress.none()
```

The allowlist travels with it, because a bundle stating the topology without
the policy only describes half a boundary.

This turns the attestation from a *report* into a *check*: the driver compares
the networks actually attached against the one its spec asked for. "One
network, named X" and "the network we asked for, and nothing else" are
different claims, and only the second catches a sandbox that came up somewhere
unexpected because a network creation failed and something fell back.

Two combinations are refused where they're written: mediation claimed with no
network named, and an endpoint named without claiming mediation. The second is
the interesting one — a sandbox merely *pointed at* a guard it isn't required
to go through looks identical, in a bundle, to one whose only route is that
guard.

## What the Docker driver does

- one internal network per run, no route out; the guard bridges it to an egress
  network
- read-only rootfs, all capabilities dropped, `no-new-privileges`
- non-root uid, forced regardless of what the image declares
- memory, CPU, and PID ceilings — these are ceilings, not security boundaries;
  they bound the damage a runaway agent does to the host it shares
- tmpfs over `/work/runs`, confirmed by canary readback rather than by Docker's
  record of the request
- constraints read back out of `docker inspect`, never echoed from the spec

`podman` uses the same driver, selected by binary name.

## Adding a driver

The real work isn't the seven methods. It's deciding, for each control in the
shared vocabulary, **whether you can honestly claim it and at what
`verified_by` level.**

A driver whose isolation differs should attest *different* controls, not the
same ones more weakly.

Concrete example: a runtime that shares no filesystem with the guest doesn't
need the mask machinery at all. There's no host directory to hide, so
`evidence_masked_from_sandbox` is in force *by construction* rather than by
canary — and the `/work/.` class of bug can't exist. That's a stronger claim
reached by a different route, and the vocabulary is built to let you say so.

Same for coverage. If your enforcement point sees more traffic than a CONNECT
proxy does, `records_cover` and `blocked_not_recorded` are how the bundle says
so — and because those fields already exist, a driver with better coverage
benefits without anyone touching the verdict logic.

`Egress` will need to carry the mediation *mechanism* rather than a boolean
before that works cleanly, since a packet-filter driver has no proxy endpoint
to name. See [egress.md](egress.md#what-the-records-cover-and-what-they-cant)
and issue #16.
