# Contributing

A driver for a new sandbox, a guard for a new enforcement point, or a hole in
the evidence model — all welcome, and none of them need our permission.

## The one thing to internalise

Everything here serves a single claim:

> **A bundle must never be able to understate what happened.**

A bundle that is missing records *while looking complete* is worse than one
that admits a gap, because a clean bundle gets read as proof of innocence. So
the codebase is tilted one way throughout: a layer that cannot record stops
working rather than working quietly, a check that cannot be made says so, and
where two readings are possible the pessimistic one is recorded.

If a change makes a bundle quieter about its own limits, it is going the wrong
way even if every test passes. [`docs/design/`](docs/design/README.md) explains
the rest.

## Getting set up

```bash
git clone https://github.com/watchlight-ai-beacon/watchlight-enclave
cd watchlight-enclave
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

pytest -q
cargo test --manifest-path crates/wl-enclave-egress/Cargo.toml --locked
```

You need a container runtime for the full suite. Docker, Colima and Podman all
work.

**Run the real thing before you believe the tests:**

```bash
wl-enclave -C examples/coder run --purpose "checking my change"
wl-enclave verify examples/coder/runs/<id>/bundle
```

### A warning about your laptop

Docker Desktop and Colima map file ownership permissively through virtiofs.
Native Linux does not. A container running as a fixed unprivileged uid cannot
write a bind-mounted file owned by the host user — which is why the guard once
died on startup on Linux while passing on macOS every time.

CI runs on Linux. If a change touches mounts, uids or anything the container
writes back to the host, **let CI see it before you trust it.** That is not CI
being pedantic; it is the only Linux most of us test on.

## Before you open a PR

```bash
pytest -q
cargo fmt --manifest-path crates/wl-enclave-egress/Cargo.toml
cargo clippy --manifest-path crates/wl-enclave-egress/Cargo.toml --locked --all-targets -- -D warnings
```

Then make sure your test fails without your fix. Revert the fix, watch it fail,
put it back. This is the step most worth doing and the easiest to skip — we
have shipped a test that passed because its probe was aimed at a path that did
not exist, which is indistinguishable from a test passing because the control
holds.

## Commits

Conventional subjects — `fix:`, `feat:`, `docs:`, `ci:`, `chore:`, `!` for
breaking — and every commit signed off under the
[DCO](https://developercertificate.org/):

```bash
git commit -s
```

Commit bodies are for *why*, including what you tried that did not work. The
diff covers what.

## Review

CI must be green — with one documented exception. The **end to end** job is red
right now and is not a required check, because it is reporting a real bug
([#22]): the sandbox is attested after the agent has already run, so on a fast
host the mask cannot be confirmed from inside. It is left failing rather than
marked `continue-on-error`, because masking a job that reports a real gap is
the same mistake as a bundle that looks complete while omitting records. If you
make it pass, make sure you fixed the ordering rather than the assertion.

[#22]: https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/22
 Beyond that, the questions a reviewer will actually ask:

**Does a bundle still state its own limits?** A new field that could be absent,
a new control that could be unverified, a new way a record could be dropped —
does `verify` notice, or does it stay quiet?

**Is the `verified_by` level honest?** `requested_not_readback` establishes
nothing, and that is enforced. If you reach for it, the control is not
established.

**Could a second implementation satisfy this seam while producing weaker
evidence, with nothing failing?** The question that matters most for drivers
and guards, because weaker evidence looks identical to honest evidence in a
bundle.

**What breaks for someone with a CI gate?** If `verify` got stricter, say so in
the CHANGELOG, in those words.

## Reporting a weakness in the evidence model

If you can make a bundle understate what happened, that is the most valuable
bug report this project can receive. Open an issue with the reproduction. A
`SECURITY.md` with a private disclosure route is coming; until then, if you
would rather not post it publicly, mail security@watchlight.ai.

Attestation gaps are fair game too: a control that claims more than it
established, a readback that reads back the thing we asked for, a probe that
cannot tell "the control held" from "we could not observe anything".
