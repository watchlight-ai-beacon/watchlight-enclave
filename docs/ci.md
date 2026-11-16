# Running under CI

CI is where the questions this tool answers actually get asked. The agent runs
with nobody watching, the runner already has Docker, and a merge gate needs
exactly the bit `verify` provides: exit 0 only when the bundle's verdict is
`ok`. A broken chain, an uncontained run and an incomplete bundle all exit 1,
and so does the job.

## The action

The repository root carries an `action.yml`, so the whole run-verify-upload
sequence is one step:

```yaml
name: governed-run
on: pull_request

jobs:
  agent:
    runs-on: ubuntu-latest   # Linux only: the sandbox needs the runner's Docker
    steps:
      - uses: actions/checkout@v7
      - uses: watchlight-ai-beacon/watchlight-enclave@main
        with:
          purpose: "CI: ${{ github.event.pull_request.title || github.ref_name }}"
          sign-key: ${{ secrets.WL_ENCLAVE_SIGNING_KEY }}
```

Pin `@main` to a release tag once one ships that includes the action. The
repository needs an `enclave.yaml` at its root (or point `working-directory`
at the directory holding one). `wl-enclave init` writes the scaffold.

What the step does, in order: install `wl-enclave`, run `doctor` so a broken
config fails before anything starts, run the agent in the sandbox, verify the
sealed bundle offline, upload the bundle as a workflow artifact, and only then
fail the job if either the agent exited non-zero or the bundle did not verify
`ok`. The order is deliberate: a failed run is exactly the run whose evidence
someone will want to read, so the upload happens whether or not the gate
passes.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `purpose` | — (required) | Why this run exists. Recorded in the evidence. |
| `working-directory` | `.` | Where `enclave.yaml` lives. |
| `version` | latest | `watchlight-enclave` version to install. |
| `sign-key` | unsigned | Private key contents, from a secret. See below. |
| `signer` | unset | Key id `verify` must find on the signature. |
| `require-signature` | `false` | Fail an unsigned bundle without pinning a key. |
| `upload-bundle` | `true` | Upload the bundle as an artifact. |
| `artifact-name` | `wl-enclave-evidence` | Name of that artifact. |

The one output is `bundle`: the absolute path to the sealed bundle, empty if
the run failed before producing one.

## Signing in CI

Unsigned bundles verify, but prove nothing about who produced them. To sign:

```bash
wl-enclave keygen --path ./ci-signing.key     # once, on your machine
```

Put the file's contents in a repository secret (the example above uses
`WL_ENCLAVE_SIGNING_KEY`) and delete the local file, or keep it somewhere a
laptop backup won't scatter it. The public key id that `keygen` printed is
what reviewers pin:

```bash
wl-enclave verify <downloaded bundle> --signer <that id>
```

That check runs offline, on the reviewer's machine, against the artifact
they downloaded. That is the point: they don't need runner access, repository
access, or your word.

Anyone who can read the secret can sign bundles as you, and in GitHub that
includes anyone who can change the workflows that receive it. Scope the secret
to the environment that runs the agent if your repository's trust boundary
needs that distinction.

## What the green check means, and what it doesn't

The sandbox constrains the agent. It does not constrain the workflow that
invoked it: the runner is the host, and the host can edit the governing files
mid-run (the bundle's two readings report that) or discard the bundle
entirely (an absent bundle fails the gate, so discarding is at least loud).
A reviewer who does not trust the workflow gets their guarantee from the
pinned signature plus the chain, not from the green checkmark.

Egress records cover what the guard mediates, which is HTTP CONNECT, and
`egress.attested` says so in the bundle itself. Traffic with no route is
blocked but not itemised. `docs/design/` carries the full statement of
coverage.

Linux runners only. The macOS runners GitHub hosts have no Docker daemon.
