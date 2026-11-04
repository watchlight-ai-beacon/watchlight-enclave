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
  <a href="docs/quickstart.md"><img alt="Docs" src="https://img.shields.io/badge/docs-quickstart-fbbf24" /></a>
  <a href="#"><img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-orange" /></a>
</p>

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
        +-- RuntimeDriver ....... Docker today; Podman and OpenShell next
        |
        +-- internal network .... no route anywhere except the guard
              |
   +----------+-----------------------------+
   |                                        |
   |   SANDBOX                          EGRESS GUARD
   |   no network of its own            CONNECT allowlist
   |   read-only root                   refuses private ranges
   |   every capability dropped         and 169.254.169.254
   |                                        |
   |   agent                                +--> upstream, if allowed
   |     |                                  |
   |     +-- @govern.tool(intent=...)       +--> egress.attempt record
   |           |
   |           +--> allow / deny ---------> decision record
   +----------------------------------------+
                        |
                        v
              hash-chained evidence bundle
              wl-enclave verify, offline
```

Two layers, and neither can answer for the other. Watchlight knows the agent
asked to wire money but not that it tried to reach an unlisted host; the guard
knows the reverse. A bundle is worth having because it holds both.

The same `policy:` bundle feeds both layers, so the authority rules and the
sandbox's network rules cannot drift apart.

## Repository layout

| Path | Contents |
|---|---|
| `src/wl_enclave/` | the `wl-enclave` CLI |
| `src/wl_enclave/drivers/` | runtime drivers behind one `RuntimeDriver` protocol |
| `src/wl_enclave/egress/` | egress guards behind one `EgressGuard` protocol |
| `crates/wl-enclave-egress/` | the guard itself: a CONNECT allowlist in Rust |
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
