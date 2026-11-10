<p align="center">
  <a href="https://www.watchlight.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset=".github/assets/watchlight-logo-white.svg" />
      <img alt="Watchlight" src=".github/assets/watchlight-logo-dark.svg" width="340" />
    </picture>
  </a>
</p>

<h1 align="center">Watchlight AI Enclave</h1>

<p align="center"><b>Run an agent in a box it cannot talk its way out of, and get the evidence your security review asks for — checkable offline, by someone who doesn't trust you.</b></p>

<p align="center">
  <a href="https://pypi.org/project/watchlight-enclave/"><img alt="PyPI" src="https://img.shields.io/pypi/v/watchlight-enclave?color=fbbf24" /></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue" /></a>
  <a href="#"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-fbbf24" /></a>
  <a href="docs/README.md"><img alt="Docs" src="https://img.shields.io/badge/docs-quickstart-fbbf24" /></a>
  <a href="SECURITY.md"><img alt="Security policy" src="https://img.shields.io/badge/security-policy-fbbf24" /></a>
</p>

You hand an agent a repo and a task. It can edit files, call tools, and reach
the network. Two questions follow immediately, and neither is answerable after
the fact by reading logs the agent could have written:

- **What did it actually try to reach?**
- **What was it allowed to do, and who decided?**

Enclave answers both, and produces a bundle you can hand to someone who
doesn't trust you.

```bash
pip install watchlight-enclave
```

```bash
wl-enclave init                          # writes enclave.yaml, scaffolds a policy
wl-enclave keygen                        # one key, once; runs seal signed bundles
wl-enclave run --purpose "Fix PR #412"   # runs the agent in a sandbox
wl-enclave verify runs/<id>/bundle       # checks the evidence, offline
wl-enclave hosts --since 2026-11-03      # what did it actually reach?
```

> **Status: pre-1.0.** The CLI, the `enclave.yaml` schema and the strictness of
> `verify` may each change in a minor release, and
> [`CHANGELOG.md`](CHANGELOG.md) is explicit about which of the three a release
> moved. 1.0 is gated on the manifest reaching its final shape.

## What did it reach?

The question a security review opens with. The answer comes out of verified
bundles rather than out of the agent's own logs:

```text
$ wl-enclave hosts --since 2026-11-03
wl-enclave: runs     14 verified
wl-enclave: coverage http_connect only; icmp, raw_tcp, udp had no route and are not recorded

HOST                          PORT  VERDICT TRIES      SENT      RECV  LAST IP
pastebin.com                   443  deny       20         -         -  -
example.com                    443  allow      20   34.4 kB  128.2 kB  172.66.147.243

wl-enclave: 2 host/verdict pair(s) over 40 attempt(s)
```

A run whose bundle does not verify is left out of that table **and counted in
the line above it**, because a shorter host list is the one way this command
could mislead you.

## Checking the evidence

`verify` needs no account, no network and no Watchlight:

```text
$ wl-enclave verify runs/20261105-013320-a946d0/bundle \
    --signer sha256:64b002a457502cac324bf45c7fe29b2222ed6f4552a6390dcb637b3fdaa92d77
wl-enclave: bundle   runs/20261105-013320-a946d0/bundle
wl-enclave: records  11
wl-enclave: head     7fc25cbd846f1dd1…
wl-enclave: signed   sha256:64b002a457502cac324bf45c7fe29b2222ed6f4552a6390dcb637b3fdaa92d77
wl-enclave: egress   attested: the guard was the sandbox's only route
wl-enclave:          records cover http_connect only; other traffic was blocked, not recorded
wl-enclave: controls 11/11 in force
wl-enclave: governed by sha256:c63334f542a4b405f6f8099cc7889c801d0b5969c5d4cfd0359915d15c5e627f
wl-enclave: OK — 11 records, chain intact, signed by the expected key
```

Without `--signer` that last line reads `self-signed`, and it means less than
it sounds like — the public key travels inside the bundle, so a verifying
signature says the manifest is unchanged, not who sealed it. Naming the key you
expect is the step that establishes *who*, and `verify` nags you to do it.

Inside the bundle, the agent's attempt to reach a host that wasn't allowed:

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

**One rule governs the whole design: a bundle must never be able to understate
what happened.** A bundle that quietly drops records while still looking
complete is worse than one that admits a gap, because the first invites a
reviewer to sign off and the second sends them to ask a question. Everything
below follows from that.

## Two layers

**The sandbox** decides where the agent may connect. An internal Docker network
with no route out, and an egress guard that is the only way through.

**[Watchlight](https://github.com/watchlight-ai-beacon/watchlight-de)** decides
what authority the agent has — which tools, on which resources, under whose
policy. Standard [Cedar](https://www.cedarpolicy.com/), so the policy is
readable and the decisions are deterministic.

One doesn't replace the other. Watchlight knows the agent *asked to wire
money*. The guard knows it *tried to reach pastebin.com*. Neither fact gets you
the other one, and a bundle carries both.

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

## Why you can trust it

Five things make a bundle worth more than a log file. Each one is small enough
that you can go and check it in the code.

- **Both halves of the story, in one chain.** Two components see two different
  things: what the agent was allowed to do, and what it tried to reach. Both
  get hashed into a single ordered stream. Keep them in separate systems and
  you lose the ability to read one against the other, which is usually the
  whole question. (The chain puts them in order. It does not yet carry a key
  linking one connection to one tool call — if you need that, ask on the
  tracker. It is a new field, not a redesign.)

- **The policy engine runs inside the agent.** Asking it a question is a
  function call, not a network hop, so every decision gets recorded and none
  get sampled away to keep costs down. The catch is what the agent never asks
  about at all, which the next section is blunt about.

- **It records what got through, not just what got blocked.** A log of blocked
  attempts tells you what you stopped. It leaves you guessing about what
  actually went out of the door. You get both, with the host, the port and the
  bytes each way.

- **The guard writes the record first, then forwards.** If it cannot write, it
  does not forward. So a guard that loses its record file goes dead instead of
  going quiet, and you find out immediately.

- **Four answers, not two.** `failed`: the chain is broken, so don't trust the
  file. `uncontained`: the chain is fine but isolation slipped, so trust it and
  go deal with it. `incomplete`: everything here is true, but something might
  be missing. `ok`: and only `ok` exits 0. "This file is lying" and "this file
  is honest about a gap" are very different problems, and you shouldn't have to
  guess which one you are holding.

Two more, if you want the detail —
[`docs/design/evidence.md`](docs/design/evidence.md) covers both. The same
`policy:` file feeds both layers and its hash goes into the bundle, so two runs
held to different rules can't end up looking like two runs held to the same
rules. And every control says *how* we know it was on, because "we configured
it" and "we checked it" are not the same claim.

## What it can't do yet

Read this before you build on it.

**A signature is not a completeness proof.** The hash chain catches *edits*.
The signed manifest pins the head and the count, which catches *truncation by
someone without the key*. It does not stop the key holder: truncate the chain,
write a `run.close` whose counts agree with what is left, re-seal, and the
bundle verifies as `ok` against a pinned key with a denial missing from it.

That is a real hole. There is a test that performs the forgery and asserts it
**works** (`test_a_key_holder_can_still_reseal_a_truncated_chain`), so this
limit can't quietly turn into a claim we don't have. Closing it takes a
countersignature from a witness the signer doesn't run, which is why every
manifest already carries an empty `cosignatures` list: adding one later won't
change the bundle format.
[#2–#6](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues).

So a signature means *this bundle is the one that key sealed, unaltered since* —
not *this bundle is everything that happened*, and `verify` prints the
difference.

**Traffic the topology blocks isn't recorded.** A raw socket to port 9999 has
no route, so it fails — but the guard never sees it, so there's no line in your
bundle. Blocked, but not written down — and the bundle admits that in
`blocked_not_recorded` instead of letting you assume otherwise.
[#12](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/12).

**Decision records are cooperative.** The SDK is a library the agent calls. An
agent that doesn't call it produces no decision records, and the bundle can't
tell you whether that means "made no decisions" or "went around the SDK". The
egress records don't have this problem, because the agent can't route around
the network topology. Don't read the two streams as equally strong.

**The workspace is writable**, so a run can edit the rules the *next* run gets
held to. We don't prevent that. We make it visible, by recording a hash of the
rules each run actually ran under.
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

## The other half: Watchlight

Enclave is the runtime. The authority layer it records is
**[Watchlight Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de)**
— the Cedar policy engine, the SDK an agent calls, and the MCP policy
enforcement point. If you came here for the evidence bundle, that repo is where
the *decisions* inside it come from.

Either works alone: Watchlight governs agents that run anywhere with no sandbox
involved, and Enclave produces bundles with an empty decision stream if you
never call the SDK. The same `policy:` bundle feeds both, which is why they are
better together.

## What's open, and what isn't

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

Both are **free to use, including in production and commercially.** A
commercial license is needed only to re-offer the engine itself as a hosted
authorization service.

You don't have to trust a black box to trust a decision. Policies are standard
[Cedar](https://www.cedarpolicy.com/) — open, formally specified and
deterministic — and `wl-enclave verify` reads a documented format with no
account and no network.

Signing uses a key **you** generate and keep. Nothing here depends on a key we
hold: there is none of ours to revoke, and no service to be up for `verify` to
work.

Want the engine source, an air-gapped build, or to govern a fleet in
production? [email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20AI%20Enclave).

## Security

Found a way to make a bundle understate what happened? That is the most
valuable report this project can receive, and
[`SECURITY.md`](SECURITY.md) has the private disclosure route and what we treat
as most severe. Please don't open a public issue for it.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Conventions follow the
[Watchlight Developer Edition repo](https://github.com/watchlight-ai-beacon/watchlight-de):
conventional commit subjects (`fix:`, `docs:`, `feat:`, `!` for breaking), and
every commit signed off under the
[DCO](https://developercertificate.org/) with `git commit -s`.
