# Quickstart

You'll put a badly behaved agent in a box, watch three different things stop it,
and end up with a file you can hand to a security reviewer.

Budget about fifteen minutes the first time. Most of that is a one-off Rust
build, and we'll tell you when it's coming.

*This is the docs home. Once you've done a run, the design notes in
[`design/`](design/README.md) cover how it works and why — including what a
bundle does and doesn't prove.*

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

Enclave then checks that claim instead of trusting it. After the sandbox starts
it reads the network layout back out of the runtime — the network is internal,
the sandbox is on it and nothing else, the guard is on it and on a way out — and
records the result as `egress.attested`. If it can't establish that, the bundle
says so rather than implying a boundary that wasn't there.

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
wl-enclave: sandbox 72b83cce8713  network=wl-enclave-...-int  read-only-root=True  caps-dropped=ALL
wl-enclave: egress     attested: the guard was the only route

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
wl-enclave: records  11
wl-enclave: head     15cdbefbc6455a0d…
wl-enclave: egress   attested: the guard was the sandbox's only route
wl-enclave:          records cover http_connect only; other traffic was blocked, not recorded
wl-enclave: controls 10/10 in force
wl-enclave: governed by sha256:c63334f542a4b405f6f8099cc7889c801d0b5969c5d4cfd0359915d15c5e627f
wl-enclave: OK — 11 records, chain intact, unsigned
```

No account, no network, not even Watchlight. The bundle holds these kinds of
record, because no one layer can answer for the others:

| Record | What it tells you |
|---|---|
| `sandbox.attested` | the constraints the sandbox ran under — no network of its own, read-only root, capabilities dropped, memory and PID ceilings — read back **out of Docker**, not copied from what we asked for |
| `config.attested` | a hash of `enclave.yaml` and every policy file that governed this run |
| `decision` | every authorization decision: who, what intent, which resource, allowed or denied |
| `egress.attempt` | every connection the agent tried: host, port, verdict, the rule that decided it, and the IP it resolved to |
| `egress.malformed` | a request the guard could not parse — refused, and still counted |
| `egress.tunnel` | how many bytes crossed an allowed connection, and for long ones `egress.tunnel_progress` while it is still open |
| `egress.attested` | whether the runtime *confirms* the guard was the sandbox's only route, and **what the records cover** |

That last one is what stops the others from being read for more than they
say. See [What the bundle proves](#what-the-bundle-proves-and-what-it-doesnt).

Two lines in that output are worth knowing about.

**`controls 10/10 in force`** is the attestation broken out one control at a
time, each saying whether it held *and how we know*. `runtime_readback` means it
was read out of the running system; `runtime_config_readback` means it came from
the runtime's record of what the container was asked for, which catches a
setting that never reached the daemon but is not the kernel's account of what is
in force. Anything not in force is listed underneath with the reason.

**`governed by`** is a hash of the config and policy files this run was held to.
Your workspace is writable — an agent that cannot write code cannot do the job —
so a run can edit the rules its successor will be held to. This does not prevent
that. It means two runs held to different rules cannot read as two runs held to
the same rules, and a run that widened its successor's allowlist leaves the
widening in its own evidence.

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
agent tried, the constraints the sandbox ran under, and whether the runtime
confirms the guard was its only route.

**It doesn't establish** attempts that don't speak HTTP CONNECT. A raw socket to
some arbitrary port is still refused — there's no route — but the guard can't
name it in a record, so it shows up as a failed connection inside the agent
rather than a line in your bundle. Blocked, but not described. The bundle says
this itself rather than leaving you to work it out: `records_cover` lists what
could be recorded, and `blocked_not_recorded` lists what couldn't.

**Read "attested" and "complete" as different claims.** A run can be fully
attested and still hold no record of a raw socket. The attestation also says how
strongly it was checked: `enforcement: network_topology` with `verified_by:
runtime_readback` means the layout was read back once, after the sandbox
started — so a route added later in the run wouldn't appear. A packet filter
inside the sandbox's own network namespace is what turns that into a continuous
guarantee, and where a runtime provides one, Enclave should consume its events
rather than reimplement them.

**`verify` has four answers, and they are not degrees of the same thing.**
Collapsing them would be the easiest way to make this output worthless, because
a reviewer who learns that one bad word covers everything stops reading the
word.

| Verdict | Exit | What it means |
|---|---|---|
| `OK` | 0 | the chain verifies, every control held, nothing is known to be missing |
| `INCOMPLETE` | 1 | everything the bundle says is true, and some of what happened is not in it — a dropped record, a control that could not be determined, a guard that stopped early |
| `UNCONTAINED` | 1 | the chain verifies and reports that a control did *not* hold. The evidence is trustworthy; it is telling you something bad |
| `FAILED` | 1 | the chain itself does not verify — edited, reordered, or truncated. Nothing else in the bundle can be relied on |

`UNCONTAINED` is the one worth dwelling on. It is not a weaker `FAILED`:
`FAILED` says *do not trust this file*, while `UNCONTAINED` says *trust this
file, and act on what it says*. Reporting a sandbox whose isolation slipped as
`FAILED` would tell you the opposite of the truth.

**If `route_exclusive` is `false`**, the sandbox had another path to the network.
The proxy variables were then advice it could ignore, and the egress records are
a lower bound rather than an account. `verify` says so plainly, because a bundle
that is quietly incomplete is worse than one that admits the gap.

**It's unsigned.** The chain catches edits and corruption. It does not prove who
produced it: anyone who can edit the file can also recompute the chain over
their edit, and `verify` says so rather than letting you assume otherwise.

Hash chaining also does not stop **truncation**. Drop records off the end and
what remains is a shorter, perfectly valid chain — which is why `verify`
reports what the bundle says about its own gaps (`records_dropped`, a guard
that stopped early, a control it could not confirm) rather than only checking
hashes. A signature over the sealed manifest is what closes truncation
properly, and that key belongs somewhere neither the agent nor the project
directory can reach. Signing is not implemented yet; `verify` says `unsigned`
on every bundle today, and the design is tracked in the repository's issues.

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

- [`docs/design/`](design/README.md) — the design notes. What a bundle
  actually proves, why your bundle says `incomplete`, what stops the agent
  editing its own evidence, and what to know before writing a driver.
- [`examples/coder`](../examples/coder/README.md) — the misbehaving agent from
  this guide, with a note on which layer stops each of its five attempts and
  some suggestions for breaking it on purpose, including breaking the
  attestation deliberately.
- [Watchlight Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de)
  — the engine, the policy language, and plugins for LangGraph, Pydantic AI, the
  Claude Agent SDK and others.
