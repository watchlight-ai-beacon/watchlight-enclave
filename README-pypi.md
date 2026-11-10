# Watchlight AI Enclave

**Run an agent in a box it cannot talk its way out of, and get the evidence
your security review asks for — checkable offline, by someone who doesn't trust
you.**

You hand an agent a repo and a task. It can edit files, call tools, and reach
the network. Two questions follow immediately, and neither is answerable after
the fact by reading logs the agent could have written:

- **What did it actually try to reach?**
- **What was it allowed to do, and who decided?**

Enclave runs the agent in an isolated sandbox whose only route out is a
recording egress guard, and seals what happened into a hash-chained evidence
bundle you can hand to someone who doesn't trust you.

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

That last one is the question a security review opens with, and the answer comes
out of verified bundles rather than out of the agent's own logs:

```text
$ wl-enclave hosts --since 2026-11-03
wl-enclave: runs     14 verified
wl-enclave: coverage http_connect only; icmp, raw_tcp, udp had no route and are not recorded

HOST                          PORT  VERDICT TRIES      SENT      RECV  LAST IP
pastebin.com                   443  deny       20         -         -  -
example.com                    443  allow      20   34.4 kB  128.2 kB  172.66.147.243

wl-enclave: 2 host/verdict pair(s) over 40 attempt(s)
```

If a run's bundle doesn't verify, its hosts are left out of that table **and
the count above it says so**. A short host list is the one way this command
could mislead you, so it refuses to be quietly short.

One rule drives the whole design: **a bundle must never be able to understate
what happened.** A bundle that quietly drops records while still looking
complete is worse than one that admits a gap. The first gets a reviewer to sign
off; the second gets them to ask a question. That's why `verify` gives four
answers instead of two: `failed`, `uncontained`, `incomplete`, `ok`. Only `ok`
exits 0.

`verify` needs no account, no network and no Watchlight.

## Requirements

Python 3.10+, and a container runtime (Docker or Colima) for `run`. `verify`
needs neither.

## Documentation

Everything lives in the repository: the quickstart, what a bundle proves, the
trust boundaries, the control vocabulary, egress coverage, and how to write a
driver for a new sandbox.

**https://github.com/watchlight-ai-beacon/watchlight-enclave**

- [Quickstart](https://github.com/watchlight-ai-beacon/watchlight-enclave/blob/main/docs/README.md)
- [What a bundle proves, and what it does not](https://github.com/watchlight-ai-beacon/watchlight-enclave/blob/main/docs/design/evidence.md)
- [Changelog](https://github.com/watchlight-ai-beacon/watchlight-enclave/blob/main/CHANGELOG.md) — including the three contracts this project versions separately
- [Security policy](https://github.com/watchlight-ai-beacon/watchlight-enclave/blob/main/SECURITY.md)

## Status

Early development, pre-1.0. The CLI, the `enclave.yaml` schema and how strictly
`verify` reads a bundle can each change in a minor release, and the changelog
always says which of the three moved. 1.0 waits on the manifest reaching its
final shape.

One limit worth knowing up front. A signature means *this bundle is the one
that key sealed, and nobody has touched it since*. It does not mean *this
bundle is everything that happened*. Whoever holds the key can cut the chain
short and re-seal it, which is why the format already carries a `cosignatures`
slot for a witness it doesn't have yet. The repository is blunt about this one
and the rest of the known gaps.

## License

Apache-2.0. The CLI, the evidence format and its offline verifier are all open.
Two compiled dependencies — the Cedar decision engine and the MCP policy
enforcement runtime — ship under the
[Watchlight Developer Edition license](https://github.com/watchlight-ai-beacon/watchlight-de),
free to use including in production and commercially.
