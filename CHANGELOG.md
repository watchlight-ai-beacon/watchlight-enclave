# Changelog

Notable changes to Watchlight AI Enclave. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Three contracts, versioned separately

This project has three promises, and only the first is what the version number
on the tag tracks. Knowing which one a change touches is the difference between
a routine upgrade and a broken pipeline.

**1. The CLI surface and `enclave.yaml` schema.** What the tag versions.
Pre-1.0, these may change in a minor release.

**2. How strictly `wl-enclave verify` reads a bundle.** Not covered by the
format version, and the one most likely to surprise you: *a stricter verifier
is a breaking change for a CI gate even when the bundle format is identical.* A
bundle that exited 0 on one version can exit 1 on the next because the verifier
learned to notice something it used to miss. Every release that tightens
`verify` says so under **Verifier** below, in those words.

**3. The bundle format**, currently `wl-enclave-evidence/1`. This moves only
when an older verifier would *misread* a newer bundle. Adding a field is not a
bump, because old verifiers ignore unknown fields. Changing what an existing
field means is a bump. This number has to age well: a bundle in someone's
compliance archive must stay verifiable for as long as they keep it.

1.0 is gated on signing ([#2–#6]), which changes the manifest. Promising format
stability before the manifest has its final shape would mean breaking that
promise immediately.

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-11-05

First tagged version. Previously unreleased, so there is no upgrade path to
describe — but the entries below are the state of the three contracts as of
this tag.

### Evidence

- **Four verdicts instead of a boolean.** `OK`, `INCOMPLETE`, `UNCONTAINED`,
  `FAILED`, as the worst of three independent claims (integrity, containment,
  completeness). Only `OK` exits 0, so a CI gate can branch on the exit code
  alone. `UNCONTAINED` is deliberately not a milder `FAILED`: `FAILED` means
  *do not trust this file*, `UNCONTAINED` means *trust it and act on what it
  says*.
- **Named controls with provenance.** Each control records whether it was in
  force *and how that was established* — `runtime_readback`,
  `network_topology`, `runtime_config_readback`, or
  `requested_not_readback`. The last one establishes nothing, and that is
  enforced rather than documented: a control resting on it is reported as
  unverified whatever it claims.
- **Containment and witnessing are separate claims.** A guard that dies on an
  internal network leaves the sandbox *more* contained and *less* witnessed, so
  that reads `INCOMPLETE`, not `UNCONTAINED`.
- **Governing digests.** `config.attested` records the digest of `enclave.yaml`
  and every policy file that governed the run.
- **The guard build is identified.** `egress.guard_started` carries the image
  digest the daemon ran (not self-reported, so the guard cannot lie about it)
  and the version the binary announced on startup (self-reported, but the only
  one that survives an image rebuilt under the same tag).

### Verifier

Stated here because this is the section future releases will use to warn you.

- **`verify` requires records that must exist to exist.** A run must have
  exactly one terminal record; a guard that started owes an attestation; a
  `run.close` tally is cross-checked against the chain. Without these,
  absence was indistinguishable from compliance and the emptiest bundle looked
  like the cleanest one.
- **`run.error` caps at `INCOMPLETE`.** A run that died during startup attested
  nothing, and the absence of those records is not evidence of a clean run.
- **Unrecognised control names are reported** rather than sorted into a claim
  by guesswork.

### Containment

- **The sandbox never runs as root.** The driver passes `--user` regardless of
  what the image declares, because an image with no `USER` directive runs as
  uid 0 and most published base images have none. Attested as
  `runs_as_non_root`, read with `id -u` from inside rather than from the
  runtime's config.
- **The evidence mask is confirmed by effect, not by configuration.** A canary
  planted behind the mask must be unreadable from inside *and* a canary at an
  unmasked path must be readable in the same probe round — otherwise "the mask
  held" and "we could not observe anything" are the same observation.
- Read-only rootfs, all capabilities dropped, `no-new-privileges`, and an
  internal network with the egress guard as the only route.

### Egress

- **Recording is a precondition for forwarding.** If the guard cannot record an
  attempt, it refuses the connection. A refused connection is a denial of
  service the agent can see and the bundle explains; an unrecorded one is a
  silent hole.
- **Saturation notes have their own budget**, so a flood of cheap payload-free
  connections cannot exhaust the budget that real records need and leave a
  later tunnel unrecorded.
- **Malformed requests are recorded** and claim no host, because none was
  parsed. Guessing one would put an attacker-chosen string in the field a
  reviewer reads as a destination.
- Addresses are resolved once, validated, and the validated address is dialled
  — never the hostname again, which is what DNS rebinding relies on. The
  address actually dialled is recorded.

### Known gaps

Each is stated in the bundle or the docs rather than left to be discovered.

- **Bundles are unsigned.** The chain catches edits, not truncation, and says
  nothing about origin. `verify` prints this on every run. [#2–#6]
- **Traffic blocked by topology is not recorded.** A raw socket to an arbitrary
  port has no route, so the guard never sees it: blocked, but not described.
  The bundle states this in `blocked_not_recorded`. [#12]
- **Decision records are cooperative.** The SDK is a library the agent calls.
  An agent that does not call it produces no decision records, and the bundle
  cannot distinguish that from an agent that made none. The egress records do
  not have this problem, because the agent cannot route around the network
  topology — so the two streams are not equally strong.
- **The workspace is writable**, so a run can edit the rules the next run is
  held to. Made visible with digests rather than prevented. [#13]

[Unreleased]: https://github.com/watchlight-ai-beacon/watchlight-enclave/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/watchlight-ai-beacon/watchlight-enclave/releases/tag/v0.1.0
[#2–#6]: https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/2
[#12]: https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/12
[#13]: https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/13
