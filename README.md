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
reviewer to sign off and the second sends them to ask a question. Every
tradeoff below falls out of that.

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

## What the bundle rests on

A bundle is only as good as the mechanism under each of its claims. These are
the five it rests on, stated plainly enough to check against the code.

- **Both halves of the story, in one chain.** The authority decision and the
  network attempt are recorded by different components with different vantage
  points, then hashed into one ordered stream. Holding them in separate systems
  loses exactly what you most want to ask about. (The chain orders them; it
  does not yet carry a key tying a specific connection to a specific tool call.
  If you need that join, say so on the tracker — it is a schema addition, not a
  redesign.)

- **The policy engine runs in the agent's own process.** A decision is a
  function call, not a round-trip to a service, so recording every decision the
  agent reports costs nothing and none are sampled away. What the agent does
  *not* report is the real limit, and the next section is blunt about it.

- **Allowed connections are evidence, not just denials.** Recording only blocked
  attempts answers "what did we stop" and leaves "what did it actually reach"
  to inference. Both verdicts are recorded, with host, port, and bytes each way.

- **The guard records before it forwards, and refuses to forward if it cannot
  record.** Recording is a precondition for the connection, not a side-effect.
  A guard that loses its record file stops being a route rather than becoming a
  silent one.

- **Four verdicts, not two.** `failed` means the chain is broken — don't trust
  the file. `uncontained` means the chain is intact and isolation slipped —
  trust it and act on it. `incomplete` means everything here is true and
  something may be missing. Only `ok` exits 0. A verifier that can't tell "this
  file is lying" from "this file is honest about a gap" leaves the reviewer to
  guess which they hold.

Two more properties, covered properly in
[`docs/design/evidence.md`](docs/design/evidence.md): the same `policy:` bundle
feeds both layers and its hash is recorded, so two runs held to different rules
cannot read as two runs held to the same rules; and each attested control says
*how* its state was established, because "configured" and "confirmed in force"
are different claims.

## What it does not do yet

Worth knowing before you build on it.

**A signature is not a completeness proof.** The hash chain catches *edits*.
The signed manifest pins the head and the count, which catches *truncation by
someone without the key*. It does not stop the key holder: truncate the chain,
write a `run.close` whose counts agree with what is left, re-seal, and the
bundle verifies as `ok` against a pinned key with a denial missing from it.

A test performs exactly that forgery and asserts it *succeeds*
(`test_a_key_holder_can_still_reseal_a_truncated_chain`), so the limit cannot
quietly become a claim we don't have. Closing it needs a cosignature from a
witness the signer does not run, which is why every manifest already carries an
empty `cosignatures` list — adding one later does not change the bundle format.
[#2–#6](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues).

So a signature means *this bundle is the one that key sealed, unaltered since* —
not *this bundle is everything that happened*, and `verify` prints the
difference.

**Traffic the topology blocks isn't recorded.** A raw socket to port 9999 has
no route, so it fails — but the guard never sees it, so there's no line in your
bundle. Blocked, not described, and the bundle states this about itself in
`blocked_not_recorded` rather than leaving you to find out.
[#12](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/12).

**Decision records are cooperative.** The SDK is a library the agent calls. An
agent that doesn't call it produces no decision records, and the bundle can't
tell you whether that means "made no decisions" or "went around the SDK". The
egress records don't have this problem, because the agent can't route around
the network topology. Don't read the two streams as equally strong.

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

## The other half: Watchlight Developer Edition

Enclave is the runtime. The authority layer it records is
**[Watchlight Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de)**
— the Cedar policy engine, the SDK an agent calls, and the MCP policy
enforcement point. If you came here for the evidence bundle, that repo is where
the *decisions* inside it come from.

Either works alone: Watchlight governs agents that run anywhere with no sandbox
involved, and Enclave produces bundles with an empty decision stream if you
never call the SDK. The same `policy:` bundle feeds both, which is why they are
better together.

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
