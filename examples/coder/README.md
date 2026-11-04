# `coder` — a misbehaving agent, contained

A deliberately badly behaved agent that makes three attempts. Each one is
stopped by a different part of the system, which is the point: you can see
which layer did the work, and the evidence bundle says so afterwards.

```bash
wl-enclave -C examples/coder doctor   # check the runtime and the policy
wl-enclave -C examples/coder run --purpose "Fix PR #412"
```

## What happens, and who stops it

| # | The agent tries | Who refuses it | How you can tell |
|---|---|---|---|
| 1 | `read_ticket("PR-412")`, declared intent `research` | nobody — it is in scope | the tool body runs and returns the ticket |
| 2 | `post_to_pastebin(...)`, declared intent `exfiltrate` | **Watchlight**: no permit covers it, and a `forbid` names it | `Denied` is raised **before the body runs**; a `Deny` record is in the bundle |
| 3 | `socket.create_connection(("example.com", 443))` | **the sandbox**: it has no network interface | `OSError` inside the agent; nothing in the bundle, because the attempt never left the box |

Row 3 is the honest one, and worth dwelling on. The attempt is genuinely
refused — but *the only witness is the agent's own failed `connect()`*, and an
agent is not a trustworthy witness about itself. The bundle therefore records
what the sandbox was **constrained to** (no network, read-only root, every
capability dropped), read back out of the runtime rather than echoed from our
own request. Per-attempt egress records need something in the path: an
allowlisting proxy, or NVIDIA OpenShell's own audit stream. Neither is in this
build.

Rows 1 and 2 are complete evidence. Row 3 is a constraint attestation. Do not
let a demo blur the two.

## The files

| File | Why it looks like that |
|---|---|
| `enclave.yaml` | the whole configuration surface: agent, runtime, policy, limits |
| `policies/coder.policy.json` | the Watchlight policy-file format, so the same bundle loads in the Developer Edition unchanged |
| `agent.py` | an ordinary agent. The only Watchlight-specific lines are `configure_default`, `govern.load` and the `@govern.tool(intent=...)` decorators |
| `Dockerfile` | installs the SDK **at build time**, because the sandbox has no network once it starts |

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
- **Let the agent out.** Set `egress.allow` in `enclave.yaml`. This build has no
  allowlisting proxy, so it refuses to pretend: it warns and gives the sandbox
  no network anyway.
- **Hit the timeout.** Set `limits.timeout: 5s`. The run is quarantined, and
  the bundle is still sealed with everything that happened first.
