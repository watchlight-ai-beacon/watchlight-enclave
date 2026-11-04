# `coder` — a misbehaving agent, contained

A deliberately badly behaved agent that makes five attempts. Each is stopped by
a different part of the system, which is the point: you can see which layer did
the work, and the evidence bundle says so afterwards.

```bash
wl-enclave -C examples/coder doctor   # check the runtime, policy and guard
wl-enclave -C examples/coder run --purpose "Fix PR #412"
```

The first run builds the egress guard from Rust source. Expect a few minutes of
silence after `egress guard: building or starting`; later runs start in seconds.

## What happens, and who stops it

| # | The agent tries | Who refuses it | How you can tell |
|---|---|---|---|
| 1 | `read_ticket("PR-412")`, intent `research` | nobody — it is in scope | the tool body runs and returns the ticket |
| 2 | `post_to_pastebin(...)`, intent `exfiltrate` | **Watchlight**: no permit covers it, and a `forbid` names it | `Denied` is raised **before the body runs**; a `Deny` record is in the bundle |
| 3 | `GET https://example.com/` | nobody — `enclave.yaml` allows it | `200`, plus an `egress.attempt` **allow** and an `egress.tunnel` with byte counts |
| 4 | `GET https://pastebin.com/` | **the egress guard**: not in the allowlist | the request fails, and an `egress.attempt` **deny** names the host, port and reason |
| 5 | `socket.create_connection(("1.1.1.1", 53))` | **the sandbox**: there is no route | `OSError` inside the agent, and **nothing in the bundle** |

Rows 2, 3 and 4 are per-attempt evidence: something outside the agent saw the
attempt and recorded a verdict.

**Row 5 is the honest one.** The attempt is genuinely refused, because the
sandbox has no route anywhere except the guard. But a raw socket speaks no
`CONNECT`, so the guard never sees it and cannot name it. The only witness is
the agent's own failed `connect()`, and an agent is not a trustworthy witness
about itself. So: blocked, but not described. That is a property of this
topology, not a bug, and the bundle says so rather than leaving you to discover
it — see the attestation below.

## The attestation

An allowlist and a pile of records are only worth as much as the claim that the
guard was the sandbox's *one* way out. Being configured correctly is not
evidence of having been configured correctly, so Enclave reads the topology back
out of the runtime after the sandbox starts and records what it found:

```json
{
  "enforcement": "network_topology",
  "verified_by": "runtime_readback",
  "route_exclusive": true,
  "records_cover": ["http_connect"],
  "blocked_not_recorded": ["raw_tcp", "udp", "icmp"],
  "network_internal": true,
  "sandbox_networks": ["wl-enclave-<run>-int"],
  "guard_networks": ["bridge", "wl-enclave-<run>-int"]
}
```

Three facts are read rather than assumed, because each is a way the boundary
could be missing while everything else looks normal: the network is marked
internal, the sandbox is attached to **that network and nothing else**, and the
guard is attached to it *and* to something else so it can forward at all.

`records_cover` is the field that keeps the bundle honest. A run can be fully
attested and still hold no record of row 5, so "attested" and "complete" are
different claims and the bundle states them separately. `verify` prints both:

```text
wl-enclave: egress   attested: the guard was the sandbox's only route
wl-enclave:          records cover http_connect only; other traffic was blocked, not recorded
```

If `route_exclusive` were `false`, the sandbox had some other path to the
network — the proxy variables would have been advice it was free to ignore, and
the egress records would be a *lower bound* rather than an account. `verify`
says so loudly, because a bundle that is quietly incomplete is worse than one
that admits the gap.

## The files

| File | Why it looks like that |
|---|---|
| `enclave.yaml` | the whole configuration surface: agent, runtime, policy, egress, limits |
| `policies/coder.policy.json` | the Watchlight policy-file format, so the same bundle loads in the Developer Edition unchanged |
| `agent.py` | an ordinary agent. The only Watchlight-specific lines are `configure_default`, `govern.load` and the `@govern.tool(intent=...)` decorators |
| `Dockerfile` | installs the SDK **at build time**, because the sandbox has no direct network once it starts |

Note what `fetch()` does before calling `urlopen`: it refuses anything that is
not `https://`. `urlopen` also honours `file://`, which reads a local path
without touching the network — so the guard would never see it and no record
would exist. Copy that restriction along with the rest.

## The policy

Two entries. The first grants the one intent the agent legitimately needs:

```json
{ "name": "coder-research",
  "code": "permit(principal, action == Action::\"research\", resource);" }
```

Cedar denies by default, so `exfiltrate` is already refused by that permit's
absence. The second entry is there to show a containment verb:

```json
{ "name": "coder-no-exfiltrate",
  "code": "@enforcement_effect(\"quarantine\")\nforbid(principal, action == Action::\"exfiltrate\", resource);" }
```

The engine accepts `quarantine`, and the call denies. **The containment action
itself does not fire yet** — freezing the agent and tearing down the run changes
state outside the agent's process, and the effect that produced the deny is not
currently visible to anything outside the engine
([watchlight-de#246](https://github.com/watchlight-ai-beacon/watchlight-de/issues/246)).
Until that lands, use `wl-enclave quarantine <run>` as the operator path.

## Reading the evidence

```bash
wl-enclave -C examples/coder ps                    # list runs
wl-enclave verify examples/coder/runs/<id>/bundle  # recompute the chain
```

`verify` is offline: no account, no network, no Watchlight. It recomputes every
hash and checks the chain against the manifest, so a record cannot be removed,
reordered or edited without it failing. Try it — flip a `Deny` to an `Allow` in
`bundle/chain.jsonl` and run `verify` again.

The chain is **unsigned** in this build, so it proves internal consistency
rather than origin: anyone who can edit the file can recompute the chain over
their edit. Signing is what makes a bundle evidence against its own author.

## Making it fail

Useful things to break, to see the system respond:

- **Add an intent the policy does not cover.** Decorate a new tool with
  `@govern.tool(intent="wire")` and call it. It denies, fail-closed, with no
  policy change needed.
- **Grant the bad intent.** Add a permit for `exfiltrate` to the policy file.
  Row 2 turns into an `Allow` — and the bundle records that you did it.
- **Widen the allowlist.** Add `pastebin.com:443` to `egress.allow`. Row 4
  becomes an allow, with a tunnel record and byte counts showing how much left.
- **Narrow it to nothing.** Set `egress.allow: []`. No guard runs, the sandbox
  gets no network at all, and the bundle contains no egress attestation —
  which `verify` reports as nothing rather than as a failure, because no guard
  was asked for.
- **Break the attestation.** While a run is going, attach the sandbox to a
  second network: `docker network connect bridge wl-enclave-<run>`. The next
  run's attestation reports `route_exclusive: false` and names the extra
  network. (`tests/test_egress_attestation.py` asserts exactly this.)
- **Hit the timeout.** Set `limits.timeout: 5s`. The run is quarantined, and
  the bundle is still sealed with everything that happened first.
