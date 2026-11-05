# Trust boundaries

The adversary is the agent in the sandbox. Assume arbitrary code execution
inside the container, full knowledge of this design, and active attempts to
reach the network unrecorded, to make the bundle understate what it did, to
reach its own evidence, and to influence the next run.

## Who can write where

```text
                      HOST (wl-enclave process)
   runs/<id>/
     evidence/   <--- the sandbox writes here.  THE ONE AGENT-CONTROLLED PATH
     guard/      <--- the guard writes here.    never mounted into the sandbox
     bundle/     <--- the host writes here.     never mounted into the sandbox
```

`evidence/` has to be writable by the sandbox, because the Watchlight SDK runs
inside the sandbox and that is where it writes its decision trail. Everything
about how decisions are handled follows from that one fact.

`guard/` is deliberately not under `evidence/`. The guard exists to be a
witness the agent cannot influence, and a witness whose notes the subject can
edit is not one. Sharing the directory would let the agent truncate the file,
or unlink and recreate it so the guard went on writing to an orphaned inode
while the host read the agent's version.

## The mask, and why it exists at all

The project root is mounted read-write at `/work` so the agent can do its job,
and `runs/` sits inside the project root. Without intervention the agent could
open `/work/runs/<id>/bundle/chain.jsonl` and rewrite the chain describing
itself while the run was still going.

A tmpfs is therefore mounted over `/work/runs`. Three things are worth knowing:

1. **Argv order is not the mechanism.** The daemon sorts mount points by
   destination path length, so a shorter bind target is always mounted before a
   path nested inside it, whatever order they were given in. The invariant that
   matters is *nesting*: a mask must be strictly below a bind target, or it
   collides with the mount instead of covering it. That is enforced on the spec.
2. **The runtime's record of a mask is not the mask.** A tmpfs destination of
   `/work/.` is accepted by the daemon, reported faithfully under
   `HostConfig.Tmpfs`, and masks nothing — the bind is mounted last and wins.
   Every check based on the runtime's record of the request passes.
3. **So the mask is confirmed by its effect.** A canary file is planted on the
   host behind each mask and read back from inside the sandbox. A *second*
   canary is planted at an unmasked path and must be readable in the same probe
   round — without that positive control, "the canary was unreadable" and "the
   sandbox could not be observed at all" are the same observation, and the
   second must not be reported as the first.

This machinery exists because the filesystem is shared. A runtime that shares
no filesystem with the guest would make it unnecessary rather than better.

## Agent-authored records are not trusted as given

Decisions arrive through `evidence/`, so at the ingest boundary they are:

- **bounded** — a cap on records and on field length, because an unbounded
  field is an unbounded chain and a loop can bury the records a reviewer came
  for;
- **reduced to known fields** — an unrecognised key in an agent-authored record
  is something a reader might believe, so it is dropped rather than carried;
- **scrubbed of control characters** — the chain is line-delimited JSON, and a
  newline inside a value is how one record becomes two;
- **stamped with provenance last**, so `asserted_by: "sandbox"` overwrites
  rather than merges with whatever the record claimed on that subject. A
  reviewer must never have to guess which records the subject of the
  investigation wrote about itself;
- **read without following symlinks** — the sandbox owns the contents of that
  directory, so it can replace the audit file with a link to a sibling it is
  not supposed to reach. Opened `O_NOFOLLOW`, with the file type checked on the
  descriptor so there is no window between the test and the read.

The record *type* is set by the host, not taken from the file. An agent writing
`{"event": "sandbox.attested", ...}` gets a `decision` record, because
`verify()` keys controls off the host-set type.

## What the host trusts, and what that costs

The host process is trusted. It writes the chain, holds the records, and seals
the bundle. A bundle therefore proves things about the **agent**, not about the
operator — and it cannot prove anything about either while unsigned, since the
chain can be recomputed over an edit by whoever can edit it.

This is the boundary most worth moving. Signing with a key the operator holds
makes a bundle evidence against the agent; making it evidence against the
operator requires a key the operator cannot wield alone. Those are different
claims and the output should never blur them. See issues #2–#6.

The guard is a second trust domain already — separate container, separate
network, separate directory — but not yet a separate *signer*, so the host
could drop a guard record. Closing that is #6.

## Known-weaker-than-it-sounds

- The agent currently runs as **root inside the container**. Capabilities are
  all dropped and `no-new-privileges` is set, so root cannot unmount the mask,
  but the mask should not have to rely on "root has no capabilities".
- `/work/policies` and `/policy` are the same inodes; the first is writable.
  The governing digest is taken once at open, so tampering *within* a run is
  not yet visible — only tampering that affects the next run.
