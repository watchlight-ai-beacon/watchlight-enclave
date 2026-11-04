# Watchlight AI Enclave

**A governed, isolated runtime for autonomous AI agents.**

Watchlight AI Enclave runs an agent inside a sandbox and puts a policy decision
point in front of every tool call it makes. Two layers enforce at once: the
sandbox decides where the agent may connect, and
[Watchlight](https://github.com/watchlight-ai-beacon/watchlight-de) decides what
authority it has. Every run produces a verifiable evidence bundle covering both.

> **Status: early development.** No releases yet. The CLI, the config format and
> the evidence bundle are all subject to change.

## Quick start

```bash
wl-enclave init                        # write enclave.yaml, scaffold a policy
wl-enclave run --purpose "Fix PR #412" # run the agent in a sandbox
wl-enclave verify runs/<id>/bundle     # check the evidence offline
```

See [`docs/quickstart.md`](docs/quickstart.md).

## How it fits together

```text
  wl-enclave run
        |
        +--> RuntimeDriver (Docker today; Podman, OpenShell next)
              |
              +--> [ SANDBOX BOUNDARY ]
                   |
                   |  agent harness  --stdio JSON-RPC-->  MCP interception
                   |                                        |
                   |                                        +--> policy decision
                   |                                        +--> evidence record
                   |
                   +-- egress: only what enclave.yaml allows
```

The same `policy:` bundle feeds both layers, so the authority rules and the
sandbox's network rules cannot drift apart.

## Repository layout

| Path | Contents |
|---|---|
| `src/wl_enclave/` | the `wl-enclave` CLI |
| `src/wl_enclave/drivers/` | runtime drivers behind one `RuntimeDriver` protocol |
| `docs/` | quickstart and reference |
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

Nothing here requires trusting a black box to trust a decision. Policies are
standard [Cedar](https://www.cedarpolicy.com/) — open, formally specified and
deterministic. The evidence format is documented and verifiable with
`wl-enclave verify`, which needs no account and no network. Signing keys are the
part we hold; the format you can read yourself.

Want the engine source, an air-gapped build, or to govern a fleet in
production? [email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20AI%20Enclave).

## Contributing

Conventions follow the
[Watchlight Developer Edition repo](https://github.com/watchlight-ai-beacon/watchlight-de):
conventional commit subjects (`fix:`, `docs:`, `feat:`, `!` for breaking), and
every commit signed off under the
[DCO](https://developercertificate.org/) with `git commit -s`.
