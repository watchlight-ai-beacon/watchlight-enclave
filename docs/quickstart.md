# Quickstart

You'll put a badly behaved agent in a box, watch three different things stop it,
and end up with a file you can hand to a security reviewer.

Budget about fifteen minutes the first time. Most of that is a one-off Rust
build, and we'll tell you when it's coming.

## Before you start

You need a container runtime. Docker is the default because you probably
already have it — Docker Desktop, Colima and Podman all work.

```bash
curl -fsSL https://get.watchlight.ai/wl-enclave | sh
```

> **Not published yet.** Until the first release, install from a clone:
>
> ```bash
> git clone git@github.com:watchlight-ai-beacon/watchlight-enclave.git
> cd watchlight-enclave
> uv venv && uv pip install -e .
> ```
>
> That puts `wl-enclave` in `.venv/bin`. Either activate the venv or call it by
> path.

## 1. Make a workspace

```bash
mkdir my-agent && cd my-agent
wl-enclave init
```

Two files, and nothing else:

```text
enclave.yaml                     the whole configuration surface
policies/my-agent.policy.json    what the agent is allowed to do
```

The policy file is in Watchlight's own format, so the same bundle works
unchanged in the
[Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de).
You're not learning a format that only lives here.

Now check your machine:

```bash
wl-enclave doctor
```

```text
wl-enclave: config    OK   enclave.yaml
wl-enclave: runtime   OK   docker
wl-enclave: policy    OK   1 file(s) in policies/
wl-enclave: egress    OK   none allowed (the sandbox gets no network)
```

`doctor` tells you everything that's wrong in one pass. If you've broken three
things, you'll see three lines, not the first one and a shrug.

## 2. Govern your agent

An Enclave agent is a normal program. Three lines make it governed:

```python
from watchlight import Denied, configure_default, govern

configure_default(agent="my-agent")              # the name on every record
govern.load("/policy/my-agent.policy.json")      # the bundle Enclave mounted

@govern.tool(intent="research")                  # what this tool is *for*
def read_ticket(ticket: str) -> str:
    return fetch(ticket)
```

That `intent=` is the whole idea. You're not writing `if user.is_admin`. You're
declaring what a tool is for, and the policy decides separately whether this
agent may do that right now.

A tool whose intent no policy permits never runs:

```python
@govern.tool(intent="exfiltrate")
def post_to_pastebin(payload: str) -> str:
    return upload(payload)                       # never reached

try:
    post_to_pastebin(secrets)
except Denied as exc:
    print(exc)                                   # already recorded
```

The body doesn't execute. The decision is on disk before your `except` runs.

Cedar denies by default, so you grant intents as the agent earns them. You never
have to remember to close something.

### One gotcha

Install the SDK **when you build the image**, not at run time. The sandbox has
no network, so nothing can be fetched once it starts:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir "watchlight==0.15.0"
WORKDIR /work
```

Pin the version. The evidence bundle is a record of what ran, and "whatever
`latest` was that morning" isn't something anyone can audit later.

## 3. Decide who it may talk to

Leave `egress.allow` empty and the sandbox gets no network at all. That's a fine
place to start.

When the agent needs the outside world, name exactly what it needs:

```yaml
egress:
  allow:
    - api.anthropic.com:443
```

Enclave then starts a guard beside the sandbox and puts the sandbox on an
internal network with **no route anywhere except the guard**. Every connection
attempt is checked against that list and recorded either way.

This is worth being precise about, because it's the difference between a setting
and a boundary. Setting `HTTPS_PROXY` on a normal container is a *request* —
code inside can ignore it and open a socket directly. Here there's nowhere else
for a packet to go. An agent that ignores the proxy doesn't escape; it just
fails to connect.

The guard also refuses an allowlisted hostname that resolves somewhere it
shouldn't: loopback, your private ranges, and `169.254.169.254` — the cloud
metadata address that hands out credentials to anyone who asks. It resolves
once, checks the answer, then connects to *that address*, so a DNS answer can't
change under it between the check and the connection.

## 4. Run it

```bash
wl-enclave run --purpose "Fix PR #412"
```

> **The first run with `egress.allow` set builds the guard from Rust source.**
> Expect several minutes of silence after `egress guard: building or starting`.
> It's cached afterwards — later runs start in seconds.

```text
wl-enclave: run 20261104-204622-f49e25  agent=coder  runtime=docker
wl-enclave: purpose: Fix PR #412
wl-enclave: egress guard: wl-enclave-...-egress:8080 on wl-enclave-...-int
wl-enclave: sandbox 72b83cce8713  network=none  read-only-root=True  caps-dropped=ALL

wl-enclave: decisions: 1 allow, 1 deny
wl-enclave: egress:    1 allow, 1 deny
wl-enclave: exit 0
wl-enclave: bundle   runs/20261104-204622-f49e25/bundle
```

`--purpose` goes into the evidence. It's the answer to "why was this agent
running at all", which is the first thing anyone asks after an incident, and the
hardest thing to reconstruct later.

## 5. Read the evidence

```bash
wl-enclave verify runs/<id>/bundle
```

```text
wl-enclave: records  9
wl-enclave: head     1a25c724d4101ebf…
wl-enclave: OK — 9 records, chain intact, unsigned
```

No account, no network, not even Watchlight. The bundle holds three kinds of
record, because three different things were watching:

| Record | What it tells you |
|---|---|
| `sandbox.attested` | the constraints the sandbox ran under — no network, read-only root, capabilities dropped, memory and PID ceilings — read back **out of Docker**, not copied from what we asked for |
| `decision` | every authorization decision: who, what intent, which resource, allowed or denied |
| `egress.attempt` | every connection the agent tried: host, port, verdict, and the rule that decided it |

Each record is chained to the one before. Change one and every hash after it
stops matching. Try it:

```bash
cp -r runs/<id>/bundle /tmp/forged
# open /tmp/forged/chain.jsonl and change a "Deny" to "Allow"
wl-enclave verify /tmp/forged
```

```text
            - record 3: hash 3835934e9d2b… does not match its content,
              which hashes to 23bc2a012f22… (the record was edited)
wl-enclave: FAILED — 1 problem(s)
```

### What the bundle proves, and what it doesn't

Worth reading once. Overclaiming here is how evidence loses the person you
handed it to.

**It establishes** every authorization decision, every HTTPS destination the
agent tried, and the constraints the sandbox ran under.

**It doesn't establish** attempts that don't speak HTTP CONNECT. A raw socket to
some arbitrary port is still refused — there's no route — but the guard can't
name it in a record, so it shows up as a failed connection inside the agent
rather than a line in your bundle. Blocked, but not described.

**It's unsigned.** The chain catches edits and corruption. It does not prove who
produced it: anyone who can edit the file can also recompute the chain over
their edit, and `verify` says so rather than letting you assume otherwise. A
signature is what makes a bundle evidence against its own author, and that key
belongs somewhere the agent's machine can't reach.

## Day-to-day

| Command | What it's for |
|---|---|
| `wl-enclave ps` | every run, newest first, with whether its bundle still verifies |
| `wl-enclave logs <run>` | what the agent printed |
| `wl-enclave quarantine <run>` | kill it now, and seal the evidence that already exists |
| `wl-enclave evidence export --run <run>` | archive a bundle; refuses if it doesn't verify |

A run that outruns `limits.timeout` is quarantined for you, and its bundle is
still sealed with everything that happened first. Nothing is lost because an
agent hung.

Run ids accept any unique prefix, so `wl-enclave logs 2026` works if there's
only one match.

## Next

- [`examples/coder`](../examples/coder/README.md) — the misbehaving agent from
  this guide, with a note on which layer stops each of its five attempts and
  some suggestions for breaking it on purpose.
- [Watchlight Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de)
  — the engine, the policy language, and plugins for LangGraph, Pydantic AI, the
  Claude Agent SDK and others.
