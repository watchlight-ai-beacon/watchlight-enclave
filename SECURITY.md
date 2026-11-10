# Security policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue or pull
request.

- **On GitHub:** use [Report a vulnerability](https://github.com/watchlight-ai-beacon/watchlight-enclave/security/advisories/new)
  on this repository's Security tab.
- **By email:** security@watchlight.ai

Include a minimal reproduction where you can. **Do not include secrets, tokens
or private data** — and note that an evidence bundle is not private data by
design, so attaching one is usually the clearest reproduction you can give.
Check it first: `enclave.yaml`, your policy file and your own host allowlist
travel inside the bundle, and a signing key never does.

## What we treat as most severe

This project exists to make one failure impossible, so a report of that failure
gets the fastest response we can give:

**A bundle that understates what happened while still verifying.** Any way to
make `wl-enclave verify` exit 0 on a bundle that is missing records, or report
`ok` where a record was removed, altered or never written, is the highest
severity class here — above remote code execution in the CLI. A bundle that
admits a gap is working correctly; one that hides a gap invites a reviewer to
sign off on something that did not happen.

Concretely, we want to hear about:

- a chain, manifest or signature check that can be made to pass over content it
  does not actually cover;
- a way for the agent to suppress, forge or reorder a record the guard writes,
  or to reach the network without the guard recording it;
- a way out of the sandbox, or to read the operator's signing key from inside
  it;
- `verify` reporting a stronger state than the evidence supports — `ok` instead
  of `incomplete`, or `signed by the expected key` instead of `self-signed`.

**Already known, so not a report:** a holder of the signing key can truncate
the chain, forge a matching `run.close`, re-seal and verify `ok` against a
pinned key. This is documented in the README and in `src/wl_enclave/signing.py`,
and there is a test that performs the forgery and asserts it *succeeds*
(`test_a_key_holder_can_still_reseal_a_truncated_chain`) so the limit cannot
quietly become a claim we do not have. Closing it needs a cosignature from a
witness the signer does not run, tracked in
[#2–#6](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues). A
way to do the same thing *without* the key is very much a report.

Traffic the network topology blocks but the guard never sees is also known and
stated in each bundle's own `blocked_not_recorded` field
([#12](https://github.com/watchlight-ai-beacon/watchlight-enclave/issues/12)).

## What happens next

- We acknowledge your report within **2 business days**.
- We give you an initial assessment within **5 business days**.
- We fix accepted issues and publish a GitHub Security Advisory, with a CVE
  where appropriate, when the fixed release is out.
- We aim to release a fix within **7 days** for critical issues, **30 days** for
  high and **90 days** for the rest.
- We disclose no later than **90 days** after we accept a report, unless we
  agree a different date with you.
- We credit reporters who want to be credited.

When a fix changes what `verify` accepts, the release notes say so under
**Verifier** in [`CHANGELOG.md`](CHANGELOG.md). A security fix that makes the
verifier stricter will break a CI gate that was passing, and we would rather
you read that in the notes than discover it in a pipeline.

## Scope

Everything published from this repository:

- `watchlight-enclave` (PyPI) — the CLI, the evidence format and its verifier;
- `wl-enclave-egress`, the Rust egress guard in `crates/`;
- the sandbox topology and the container images built here;
- the examples.

The authorization engine (`watchlight-engine`) and the MCP runtime
(`watchlight-mcp`) ship as compiled packages from the
[Watchlight Developer Edition repository](https://github.com/watchlight-ai-beacon/watchlight-de).
Vulnerabilities in them are equally in scope; report them the same way, to the
same address.

Reports about Watchlight Cloud or Watchlight AI Beacon are welcome at the same
address.

## Supported versions

We fix the latest minor release. Upgrade to the newest release to receive
security fixes, and please check that the issue still occurs there before
reporting.

Pre-1.0, the bundle format is `wl-enclave-evidence/1` and we intend bundles
written by any 0.x release to stay verifiable. If you find a release that
cannot read a bundle an earlier one wrote, treat that as a bug worth reporting
even if nothing is exploitable: someone's compliance archive depends on it.

## Safe harbour

We will not take legal action against good-faith research that respects user
privacy, avoids harming systems or data, and gives us reasonable time to fix
the issue before disclosure.

Running an agent inside Enclave and attacking the sandbox from the inside is
exactly the research we want. Please do it against your own installation.
