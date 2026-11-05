<p align="center">
  <a href="https://www.watchlight.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset=".github/assets/watchlight-logo-white.svg" />
      <img alt="Watchlight" src=".github/assets/watchlight-logo-dark.svg" width="340" />
    </picture>
  </a>
</p>

<h1 align="center">Watchlight AI Enclave</h1>

<p align="center"><b>Run an agent in a box it cannot talk its way out of. One command, and a bundle your security team will accept.</b></p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue" /></a>
  <a href="#"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-fbbf24" /></a>
  <a href="crates/wl-enclave-egress"><img alt="Rust" src="https://img.shields.io/badge/rust-1.82%2B-fbbf24" /></a>
  <a href="docs/README.md"><img alt="Docs" src="https://img.shields.io/badge/docs-quickstart-fbbf24" /></a>
  <a href="#"><img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-orange" /></a>
</p>

You hand an agent a repo and a task. It can edit files, call tools, and reach
the network. Two questions follow immediately, and neither is answerable after
the fact by reading logs the agent could have written:

- **What did it actually try to reach?**
- **What was it allowed to do, and who decided?**

Enclave answers both, and produces a bundle you can hand to someone who
doesn't trust you.

```bash
wl-enclave init                          # writes enclave.yaml, scaffolds a policy
wl-enclave run --purpose "Fix PR #412"   # runs the agent in a sandbox
wl-enclave verify runs/<id>/bundle       # checks the evidence, offline
```

That last command is the point. It needs no account, no network, and no
Watchlight:

```text
$ wl-enclave verify runs/20261105-013320-a946d0/bundle
wl-enclave: bundle   runs/20261105-013320-a946d0/bundle
wl-enclave: records  11
wl-enclave: head     7fc25cbd846f1dd1…
wl-enclave: egress   attested: the guard was the sandbox's only route
wl-enclave:          records cover http_connect only; other traffic was blocked, not recorded
wl-enclave: controls 11/11 in force
wl-enclave: governed by sha256:c63334f542a4b405f6f8099cc7889c801d0b5969c5d4cfd0359915d15c5e627f
wl-enclave: OK — 11 records, chain intact, unsigned
```

Inside that bundle, the agent's attempt to reach a host that wasn't on the
allowlist:

```json
{
  "seq": 9,
  "type": "egress.attempt",
  "data": {
    "host": "pastebin.com",
    "port": 443,
    "verdict": "deny",
    "reason": "pastebin.com:443 is not in the allowlist"
  },
  "prev": "5d14a325b148e3d1…",
  "hash": "9d8824737848d29d…"
}
```

The agent couldn't have suppressed that record, because it isn't the one who
wrote it.

## Two layers, and why you need both

**The sandbox** decides where the agent may connect. An internal Docker network
with no route out, and an egress guard that is the only way through.

**[Watchlight](https://github.com/watchlight-ai-beacon/watchlight-de)** decides
what authority the agent has — which tools, on which resources, under whose
policy. Standard [Cedar](https://www.cedarpolicy.com/), so the policy is
readable and the decisions are deterministic.

Neither substitutes for the other. Watchlight knows the agent *asked to wire
money*. The guard knows it *tried to reach pastebin.com*. You can't derive
either from the other, and a bundle carries both.

> **Status: early development.** No releases yet. The CLI, the config format and
> the evidence bundle are all subject to change.

## How it fits together

```text
                              YOUR MACHINE
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│ ┌────────────────────────────┐        ┌────────────────────────────┐ │
│ │ SANDBOX                    │        │ EGRESS GUARD               │ │
│ │                            │        │                            │ │
│ │ non-root uid               │        │ uid 65532                  │ │
│ │ read-only root             │        │ CONNECT allowlist          │ │
│ │ all capabilities dropped   │        │ refuses private ranges,    │ │
│ │ no-new-privileges          │        │ link-local, NAT64, and     │ │
│ │ tmpfs over its own runs/   │        │ 169.254.169.254            │ │
│ │                            │        │                            │ │
│ │  agent                     │        │ records the attempt BEFORE │ │
│ │    │                       │        │ forwarding. If it cannot   │ │
│ │    ├─ @govern.tool(...)    │        │ record, it refuses.        │ │
│ │    │                       │        │                            │ │
│ │    └─ CONNECT ═════════════╪═══════▶│ ───────────────▶ upstream  │ │
│ └─────────┬──────────────────┘        └──────────┬─────────────────┘ │
│           │                                      │                   │
│    decision records                       egress.attempt             │
│           │                                + bytes each way          │
│           ▼                                      ▼                   │
│   runs/<id>/evidence/                    runs/<id>/guard/            │
│   the agent writes here —                never mounted into          │
│   the ONLY path it can                   the sandbox                 │
│   influence                                      │                   │
│           └──────────────────┬───────────────────┘                   │
│                              ▼                                       │
│               runs/<id>/bundle/chain.jsonl                           │
│               each record hashed over the one before it              │
│                                                                      │
└──────────────────────────────┬───────────────────────────────────────┘
                               ▼
                       wl-enclave verify
            offline — no account, no network, not even Watchlight

  ═══  the sandbox has no route out except the guard (docker --internal)
  ───  a line in the evidence bundle
```

**Read it as two independent witnesses.** The left box knows the agent asked to
wire money. The right box knows it tried to reach an unlisted host. Neither can
be derived from the other, and a bundle is worth having because it holds both.

**The `═══` lines are the ones that matter.** Proxy environment variables are a
convenience for the agent, not a control — an agent that ignores them finds no
route rather than a bypass. If the route were the convenience and the variables
the control, an agent could simply not read them.


Two layers, and neither can answer for the other. Watchlight knows the agent
asked to wire money but not that it tried to reach an unlisted host; the guard
knows the reverse. A bundle is worth having because it holds both.

The same `policy:` bundle feeds both layers, so the authority rules and the
sandbox's network rules cannot drift apart. The bundle records a hash of that
file and of `enclave.yaml`, so two runs held to different rules cannot read as
two runs held to the same rules.

Each attested control says how its state was established, because "configured"
and "confirmed in force" are different claims and a bundle that cannot tell
them apart invites a reviewer to assume the stronger one. `verify` reports the
weakest claim any layer made, and distinguishes a chain that does not verify
(`FAILED`) from a chain that verifies and reports that isolation slipped
(`UNCONTAINED`) from one that is true but missing something (`INCOMPLETE`).

Bundles are not yet signed, so a bundle proves the chain is internally
consistent, not who produced it — `verify` says so on every run rather than
letting you assume otherwise.

## What it does not do yet

Worth knowing before you build on it.

**Bundles are unsigned.** The hash chain catches *edits* — change a record and
every hash after it breaks. It does nothing about *truncation*: lop records off
the end and what remains is a shorter, perfectly valid chain. `verify` says so
out loud rather than letting you assume otherwise:

```text
note: the chain is internally consistent but unsigned, so it proves nothing
      about who produced it
```

Signing is the biggest open item — issues
[#2–#6](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues).

**Traffic the topology blocks isn't recorded.** If the agent opens a raw socket
to port 9999, there's no route, so it fails. But the guard never sees it, so
there's no line in your bundle. Blocked, not described — and the bundle states
this about itself in `blocked_not_recorded` rather than leaving you to find out.
[#12](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/12).

**Decision records are cooperative.** The SDK is a library the agent calls. An
agent that doesn't call it produces no decision records, and the bundle can't
tell you whether that means "made no decisions" or "went around the SDK". The
egress records don't have this problem, because the agent can't route around the
network topology. Don't read the two streams as equally strong.

**The workspace is writable**, so a run can edit the rules the *next* run is
held to. We make that visible with digests rather than preventing it.
[#13](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/13).

## Repository layout

| Path | Contents |
|---|---|
| `src/wl_enclave/` | the `wl-enclave` CLI |
| `src/wl_enclave/drivers/` | runtime drivers behind one `RuntimeDriver` protocol |
| `src/wl_enclave/egress/` | egress guards behind one `EgressGuard` protocol |
| `crates/wl-enclave-egress/` | the guard itself: a CONNECT allowlist in Rust |
| [`docs/`](docs/README.md) | the quickstart — install, first run, reading a bundle |
| `docs/design/` | design notes — what a bundle proves, trust boundaries, the control vocabulary, egress coverage, writing a driver |
| `examples/` | runnable agents with policies |

## Open source, and the license

Everything in this repository is **open and Apache-2.0** — the `wl-enclave`
CLI, the `enclave.yaml` schema, the `RuntimeDriver` protocol and every runtime
driver, the MCP interception transport, the evidence format and its offline
verifier, and every example here. A driver for a new sandbox is a contribution
we want, and nothing about it needs our permission.

Two dependencies are **compiled**, and ship under the
[Watchlight Developer Edition license](https://github.com/watchlight-ai-beacon/watchlight-de)
rather than Apache-2.0:

| Component | What it is |
|---|---|
| `watchlight-engine` | the Cedar decision engine, in-process |
| `watchlight-mcp` | the MCP policy enforcement point runtime |

Both are **free to use, including in production and commercially.** A commercial
license is needed only to re-offer the engine itself as a hosted authorization
service.

You don't have to trust a black box to trust a decision. Policies are standard
[Cedar](https://www.cedarpolicy.com/) — open, formally specified, deterministic.
The evidence format is documented, and `wl-enclave verify` reads it with no
account and no network.

Bundles are not signed yet, so nothing in this repository depends on a key we
hold. When signing lands, the design question is whose key it is — a key the
operator holds makes a bundle evidence against the *agent*, and evidence against
the *operator* needs a key the operator can't wield alone. Those are different
claims and we won't blur them. That discussion is in the open, in issues
[#2–#6](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues).

Want the engine source, an air-gapped build, or to govern a fleet in
production? [email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20AI%20Enclave).

## Changelog

[`CHANGELOG.md`](CHANGELOG.md), which also explains the three contracts this
project versions separately — the CLI surface, how strictly `verify` reads a
bundle, and the bundle format itself. The second one is the one that will catch
you out: a stricter verifier breaks a CI gate even when the format has not
changed.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Conventions follow the
[Watchlight Developer Edition repo](https://github.com/watchlight-ai-beacon/watchlight-de):
conventional commit subjects (`fix:`, `docs:`, `feat:`, `!` for breaking), and
every commit signed off under the
[DCO](https://developercertificate.org/) with `git commit -s`.
