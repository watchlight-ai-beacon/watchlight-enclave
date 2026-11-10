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

1.0 is gated on the manifest reaching its final shape. Operator signing is in
(see 0.2.0), but witness cosignatures ([#2–#6]) are the part that decides
what a sealed manifest ultimately holds. Promising format stability before then
would mean breaking that promise immediately.

## [Unreleased]

### Fixed

- **⚠️ `verify` is stricter: a run that was stopped no longer verifies as `ok`**
  ([#35](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/35)).
  This changes the verdict on bundles you already hold, which is the second of
  the three contracts this project versions separately. **A CI gate that passed
  on a contained run will now fail.** That is the point: it was passing on
  evidence that understated what happened.

  `verify` asked how many terminal records a chain held and required exactly
  one. That counted two different things as one, and was wrong both ways.

  A run killed by `wl-enclave kill`, whose chain ends at `run.contained`
  because nothing came along to close it, counted as a single clean ending and
  verified **`ok`** — the same verdict as a run that ran to completion. The
  agent was stopped, whatever it had not done is absent, and the bundle said
  nothing about it. This is the half that mattered.

  A run stopped by its own timeout records `run.contained` and then seals with
  `run.close` and its tallies, because it genuinely did both. Counting gave two
  endings and returned **`failed`** on a sound bundle, so an operator could not
  tell "properly contained" from "broken bundle" — both exited 1.

  Both now verify `incomplete`, and the verdict says which kind of stop and
  why. `run.close` and `run.error` end a run; `run.contained` says it was
  stopped and may be the last record without being clean.

  Also now caught: **records appended after the ending**. A chain whose
  `run.close` was followed by more records described a run that had already
  ended, and verified `ok` with nothing looking for it. Truncation from the end
  was already caught by the manifest's head and count; this is the opposite
  case.

- The `INCOMPLETE — by the bundle's own account:` heading no longer claims to
  be about egress. The label was copied from the controls block above it and
  showed on every incomplete bundle, whatever the reason.

- **The sandbox is attested before the agent runs, not alongside it**
  ([#22](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/22)).
  `provision` started the container with the agent as its first process, so the
  agent was already working while `attest` read the boundary back. On a fast
  host it could finish first, and the attestation then described a container
  that no longer existed: every probe failed, which read as a sandbox that
  could not be observed and turned a healthy run into `INCOMPLETE`. The
  positive control is what caught it rather than letting it pass as a mask that
  held.

  The deeper problem was the order. The check that establishes the agent cannot
  reach its own evidence ran *after* the agent had the chance to reach it.

  The sandbox now comes up holding, with no agent code in it. `attest` reads
  the boundary out of the live container, and a new `RuntimeDriver.release()`
  starts the agent only once that is recorded. The chain is hash-linked in
  order, so `sandbox.attested` provably precedes every record the agent
  authored.

  Driver authors: `provision` must not run `spec.command`, `wait` now follows
  the agent rather than the container, and `logs` returns the agent's output.
  The sandbox outlives what it was holding for.

## [0.2.1] — 2026-11-10

**Packaging, documentation, and what `keygen` prints.** No change to
`enclave.yaml`, to how strictly `verify` reads a bundle, or to the bundle
format. Nothing here can change the verdict on a bundle you already hold. The
one behavioural change is two output labels in `keygen`, which matters only if
you parse them.

This is also the release where the repository became public.

This is the first release on PyPI: `pip install watchlight-enclave`. 0.2.0 was
tagged before the publishing workflow existed, and a publish must come from a
tag that carries it, so the first published version is this one. 0.2.0 remains
a GitHub release and an install from source; nothing was published under it.

### Added

- **`publish-pypi.yml`** — publishing over OIDC trusted publishing, so no
  long-lived API token exists in the repository or anywhere else. Manual, and
  a dry run unless told otherwise. Four gates, each refusing rather than
  warning, because a PyPI filename is permanent and a bad upload cannot be
  corrected in place, only yanked:
  - a publish must come from a `v*` tag;
  - `pyproject.toml`, `wl_enclave.__version__` and the tag must agree, and
    exactly one wheel and one sdist must name that version;
  - no key or credential material in either distribution — `wl-enclave
    keygen` writes Ed25519 private keys as `.pem` files, so a key left in the
    working tree is a real way to publish one by accident — and no wheel
    missing `evidence.py` or `signing.py`, since the verifier is the thing
    third parties are promised;
  - the built wheel is installed in a clean virtualenv and run, including
    `keygen`, which exercises the lazy `cryptography` import through the real
    entry point. An undeclared dependency would otherwise surface only when a
    user tried to sign.
- **`github-release.yml`** — release notes taken from this file rather than
  written twice. The notes state which of the three contracts a release moved,
  and a reader deciding whether an upgrade breaks their CI gate relies on that
  being accurate; a second copy drifts. A missing or empty section for the
  tagged version fails the run rather than falling back to generated notes.

### Documentation

- **[`SECURITY.md`](SECURITY.md)** — private disclosure, mirroring the
  [Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de)
  policy: same routes, same response windows, same safe harbour. It adds one
  section that policy does not need — *what we treat as most severe*. A bundle
  that understates what happened while still verifying ranks above remote code
  execution in the CLI here, so the policy says so outright, lists the four
  shapes it takes, and names the two limits that are already documented
  (key-holder re-seal, and traffic the topology blocks but the guard never
  sees) so nobody spends a weekend rediscovering them.
- **[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)** — the Developer Edition file
  verbatim, Contributor Covenant 2.1, reports to conduct@watchlight.ai.
- **A package page of its own.** `readme` points at `README-pypi.md`, 4.2 kB
  rather than 18 kB. The repository README is for someone deciding whether to
  trust the design; a package page's job is to get you installed and then send
  you to the repository, which is where the documentation lives.
- **`[project.urls]`** was absent, so the package page had no route back to the
  source. For a project whose claim is that you can read the verifier
  yourself, that is the one link that has to work.
- `CONTRIBUTING.md` told you to open a public issue for a weakness in the
  evidence model and said a security policy was coming. Both are now wrong. It
  also documents that `main` requires an approving review, and that the
  maintainer bypass does not extend to the status checks.
- The README dropped a duplicated paragraph and a status line claiming no
  releases existed, and gained a section pointing at Developer Edition for
  anyone who arrived via a bundle and wants to know where the decisions in it
  come from.

### Changed

- **`keygen` says `private key` and `public key id`**, where it said `key` and
  `key id`. One is a file to protect and the other is a string to publish, and
  the old labels left the reader to work that out. Getting it backwards goes
  wrong in both directions: pasting a private key into a ticket, or withholding
  the one value a reviewer needs in order to pin a signer. The command now also
  states that the private key stays in its file and is not copied into a
  bundle, mounted into the sandbox, or sent anywhere — the question the old
  output invited and did not answer. **If you parse `keygen` output, match on
  `public key id`.**
- `signing.exposed_by()` is documented correctly. It is the check that refuses
  a run when the signing key sits inside a directory mounted into the sandbox,
  which is the guard against an agent reading the key that signs its own
  evidence. Its docstring described the symlink case backwards, and the test
  covering that case was named for the opposite of what it asserted. The
  behaviour was right; only the description was wrong.
- The sdist is an explicit include list instead of hatchling's default, which
  is the whole working tree minus VCS ignores. The files it had been sweeping
  in were harmless — CI config, a scanner baseline — but the default is *open*,
  so anything added to the repository later would ship by default and nobody
  would find out until it was on an immutable index. `tests/` and `crates/`
  are included deliberately: the forgery tests are how a third party confirms
  the verifier refuses what it says it refuses, and the guard crate is where
  record-before-forward lives.

## [0.2.0] — 2026-11-10

### Added

- **`wl-enclave hosts [--since DATE]`** — every host the agent reached, across
  runs, with verdict, attempt count, bytes each way and the address actually
  dialled. The records existed from the first release and there was no way to
  read them back, so the product recorded the thing it is best at and could not
  show you. A run whose bundle does not verify is **excluded and announced**,
  because a shorter, tidier host list is the one way this command could
  mislead; the exit status is non-zero whenever the table is not both
  trustworthy and complete, and the guard's coverage
  (`http_connect` only) prints beside the answer rather than in a footnote.

- **Signed manifests.** `wl-enclave keygen` writes an Ed25519 key (default
  `~/.config/wl-enclave/signing.key`, mode 0600, outside both the repository
  and the bundle); `run` seals a signature over the manifest body when a key
  resolves. A key named explicitly — `--sign-key` or `$WL_ENCLAVE_SIGNING_KEY`
  — that cannot be read is an error, because sealing unsigned after being asked
  to sign is the kind of quiet downgrade this format exists to prevent. No key
  anywhere still seals unsigned, so an install that never runs `keygen` behaves
  as it did. [#2–#6]
- **`verify --signer KEY_ID`** and **`verify --require-signature`**. The first
  is the only form of the check that establishes *who* sealed a bundle. The
  second accepts any key but requires one.
- **`cosignatures` in every manifest**, written empty, and verified when
  present. A witness the signer does not run is what would make a bundle
  evidence against its operator rather than only against the agent; reserving
  and checking the slot now means adding one later changes neither the bundle
  format nor the verifier.

### Changed

- **`verify` grades signing in three steps rather than two.** The summary reads
  `unsigned`, `self-signed`, or `signed by the expected key`. `self-signed` is
  not a hedge: the public key travels inside the bundle, so a verifying
  signature establishes that the manifest is unchanged and *not* who sealed it.
  Anyone can produce a bundle in that state.
- **One manifest payload.** Four seal sites built this independently and three
  disagreed, which was survivable while the manifest was only read and is not
  once it is signed.
- New runtime dependency: `cryptography>=42.0`. Imported lazily, so verifying
  an *unsigned* bundle still works if it is missing.

### Verifier

**This release does not tighten `verify` by default.** `--signer` and
`--require-signature` are opt-in, so a gate standing on a bundle sealed by
0.1.0 keeps passing. Two new ways to fail exist once you opt in: an unsigned
bundle under `--require-signature` reads `incomplete` (everything in it is
still true; what is missing is attribution), while a signature that does not
verify, names a `key_id` its own public key does not produce, carries an
unrecognised algorithm, or belongs to a key other than the pinned one reads
`failed` (a contradiction, not a gap).

### Format

`wl-enclave-evidence/1` is unchanged. `signature` and `cosignatures` are added
fields, and a verifier that predates them reports a signed bundle as
`unsigned` — weaker than the truth, which is the only direction a stale
verifier may err.

### Known gaps

- **A signature is not a completeness proof.** The key holder can truncate the
  chain, write a `run.close` whose counts agree with what is left, re-seal, and
  the bundle verifies as `ok` against a pinned key with a denial missing.
  `tests/test_signing.py::test_a_key_holder_can_still_reseal_a_truncated_chain`
  performs that forgery and asserts it *succeeds*, so the limit cannot become a
  claim by accident. Only a witness cosignature closes it. [#2–#6]

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
  *(Addressed in part under Unreleased: manifests can now be signed, which
  moves the forger from anyone with write access to the key holder. It does not
  close truncation by the key holder.)*
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

[Unreleased]: https://github.com/watchlight-ai-beacon/watchlight-enclave/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/watchlight-ai-beacon/watchlight-enclave/releases/tag/v0.2.1
[0.2.0]: https://github.com/watchlight-ai-beacon/watchlight-enclave/releases/tag/v0.2.0
[0.1.0]: https://github.com/watchlight-ai-beacon/watchlight-enclave/releases/tag/v0.1.0
[#2–#6]: https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/2
[#12]: https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/12
[#13]: https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/13
