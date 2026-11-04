# Quickstart

From nothing to a verifiable governed run. Three commands, about five minutes,
most of it spent building the image.

## Install

```bash
curl -fsSL https://get.watchlight.ai/wl-enclave | sh
```

> **Not yet published.** Until the first release, install from a clone:
>
> ```bash
> git clone git@github.com:watchlight-ai-beacon/watchlight-enclave.git
> cd watchlight-enclave && uv venv && uv pip install -e .
> ```

You also need a container runtime. Docker is the default lane because it is
probably already installed; `wl-enclave doctor` will tell you if it is not.

## 1. Scaffold

```bash
mkdir my-agent && cd my-agent
wl-enclave init
```

That writes two files and nothing else:

- **`enclave.yaml`** — the entire configuration surface.
- **`policies/my-agent.policy.json`** — a starter policy in the Watchlight
  policy-file format, so the same bundle loads in the
  [Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de)
  unchanged.

```bash
wl-enclave doctor
```

```text
wl-enclave: config    OK   enclave.yaml
wl-enclave: runtime   OK   docker
wl-enclave: policy    OK   1 file(s) in policies/
wl-enclave: egress    OK   none allowed (the sandbox gets no network)
```

`doctor` reports every problem it finds at once, rather than failing on the
first, so one run tells you everything to fix.

## 2. Govern your agent

An Enclave agent is an ordinary program. Three lines make it governed:

```python
from watchlight import Denied, configure_default, govern

configure_default(agent="my-agent")              # the name on every record
govern.load("/policy/my-agent.policy.json")      # the bundle Enclave mounted

@govern.tool(intent="research")                  # declares what this is for
def read_ticket(ticket: str) -> str:
    return fetch(ticket)
```

A tool whose intent no policy permits is refused **before its body runs**:

```python
@govern.tool(intent="exfiltrate")
def post_to_pastebin(payload: str) -> str:
    return upload(payload)                       # never reached

try:
    post_to_pastebin(secrets)
except Denied as exc:
    print(exc)                                   # already recorded as a Deny
```

Cedar denies by default, so you grant intents as the agent earns them instead of
opening it up and narrowing later.

**Install the SDK at image build time.** The sandbox has no network once it
starts, so nothing can be fetched at run time:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir watchlight
WORKDIR /work
```

## 3. Run it

```bash
wl-enclave run --purpose "Fix PR #412"
```

```text
wl-enclave: run 20261104-204622-f49e25  agent=coder  runtime=docker
wl-enclave: purpose: Fix PR #412
wl-enclave: sandbox 72b83cce8713  network=none  read-only-root=True  caps-dropped=ALL

wl-enclave: decisions: 1 allow, 1 deny
wl-enclave: exit 0
wl-enclave: bundle   runs/20261104-204622-f49e25/bundle
wl-enclave: verify   wl-enclave verify runs/20261104-204622-f49e25/bundle
```

`--purpose` is recorded in the evidence. It is the answer to "why was this agent
running at all", which is the first question asked after an incident.

## 4. Verify the evidence

```bash
wl-enclave verify runs/<id>/bundle
```

```text
wl-enclave: records  5
wl-enclave: head     1a25c724d4101ebf…
wl-enclave: OK — 5 records, chain intact, unsigned
```

Offline: no account, no network, not even Watchlight. The bundle holds two kinds
of record, because the two layers see different things:

| Record | What it establishes |
|---|---|
| `sandbox.attested` | the constraints the sandbox is under — no network, read-only root, capabilities dropped, PID and memory ceilings — **read back out of the runtime**, not echoed from our request |
| `decision` | every authorization decision: principal, declared intent, resource, verdict, decision id |

Each record is chained to the one before it, so removing, reordering or editing
one breaks every hash that follows. Try it:

```bash
cp -r runs/<id>/bundle /tmp/forged
# flip a "Deny" to "Allow" in /tmp/forged/chain.jsonl
wl-enclave verify /tmp/forged
```

```text
            - record 3: hash 3835934e9d2b… does not match its content,
              which hashes to 23bc2a012f22… (the record was edited)
wl-enclave: FAILED — 1 problem(s)
```

### What this bundle does and does not prove

Be precise about this, because overclaiming is how evidence loses a reviewer.

**It establishes** every authorization decision the agent's tool calls produced,
and the constraints the sandbox was under while it ran.

**It does not establish** every *attempt* the agent made at the network. With no
network interface, a blocked connection leaves no record anywhere — the only
witness is the agent's own failed `connect()`, and an agent is not a trustworthy
witness about itself. Per-attempt egress evidence needs something in the path:
an allowlisting proxy, or NVIDIA OpenShell's own audit stream.

**It is unsigned**, so it proves internal consistency rather than origin. A
forger who recomputes the whole chain *and* the manifest head produces a bundle
that verifies. A signature is what makes a bundle evidence against its own
author, and the key belongs to the governed control plane rather than to the
machine the agent ran on.

## Lifecycle

| Command | Does |
|---|---|
| `wl-enclave ps` | every run, newest first, with its bundle's verification state |
| `wl-enclave logs <run>` | what the sandbox printed |
| `wl-enclave quarantine <run>` | kill it now and seal whatever evidence exists |
| `wl-enclave evidence export --run <run>` | archive the bundle, refusing if it does not verify |

A run that outlives `limits.timeout` is quarantined automatically, and its
bundle is still sealed with everything that happened first.

## Next

- [`examples/coder`](../examples/coder/README.md) — a misbehaving agent, and
  which layer stops each of its three attempts.
- [Watchlight Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de)
  — the authorization engine, policy language and framework plugins.
