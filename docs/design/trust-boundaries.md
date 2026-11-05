# Trust boundaries

**The adversary is the agent in the sandbox.** Assume it can run arbitrary
code, has read this document, and is actively trying to reach the network
unrecorded, make the bundle understate what it did, get at its own evidence,
and influence the next run.

## Who can write where

```text
runs/<id>/
  evidence/   ← the agent writes here     ONLY path it can influence
  guard/      ← the guard writes here     never mounted into the sandbox
  bundle/     ← the host writes here      never mounted into the sandbox
```

`evidence/` *has* to be writable by the agent, because the Watchlight SDK runs
inside the sandbox and that's where it writes decisions. Everything in the
"records we don't trust" section below follows from that one unavoidable fact.

`guard/` is deliberately not inside `evidence/`. The guard exists to be a
witness the agent can't influence, and a witness whose notes the suspect can
edit isn't one. If they shared a directory, the agent could truncate the
guard's file — or `unlink` and recreate it, so the guard keeps writing happily
to an orphaned inode while the host reads the agent's version instead.

## The mask

Here's the problem. We mount your project root read-write at `/work` so the
agent can do its job. But `runs/` lives inside your project root. So without
intervention:

```text
/work/runs/<id>/bundle/chain.jsonl    ← the agent can just open this and
                                        rewrite the record of itself
```

Fix: mount a tmpfs over `/work/runs`. The agent sees an empty directory.

Three things we learned the hard way.

**Argv order isn't the mechanism.** Docker sorts mount points by destination
path length, so a shorter bind target always gets mounted before anything
nested inside it, regardless of the order you pass them. What actually matters
is *nesting*: a mask has to be strictly below a bind target, or it collides
with the mount instead of covering it. We enforce that on the spec.

**Docker's record of a mask is not the mask.** This one is nasty. Ask for a
tmpfs at `/work/.` and Docker accepts it, reports it faithfully under
`HostConfig.Tmpfs`, and masks absolutely nothing — because `/work/.` normalises
to `/work`, and the bind gets mounted last, so it wins. We reproduced it: the
container's mount table showed *both* `tmpfs /work` and the virtiofs bind, and
`cat` happily printed the secret. Every check based on Docker's record of what
we asked for passed.

**So we confirm the mask by its effect.** Plant a canary file on the host
behind each mask, then try to read it from inside the sandbox. If it's
unreadable, the mask is holding.

Except — and this is the part that bit us — "unreadable" and "we couldn't
observe anything at all" look identical. A container that already exited, an
exec that got refused, an image with no `cat`: all of those return non-zero and
would have read as "mask confirmed". The control reported `in_force: true` with
our strongest provenance label from *zero actual observation*.

So there's a second canary at an *unmasked* path which must be readable in the
same probe round. If we can't read the file that's supposed to be readable, we
report "couldn't determine" rather than "confirmed". We also distinguish exit
codes, because `cat` exits 1 for a missing file but 126/127 when exec itself
failed, and the latter tells you nothing about the file.

Worth noting: this whole apparatus exists *because* the filesystem is shared. A
runtime that shares no filesystem with the guest wouldn't need it — see
[drivers.md](drivers.md#adding-a-driver).

## Records the agent writes, which we don't trust

Decisions arrive through `evidence/`, so at the ingest boundary we:

- **bound them** — caps on record count and field length, because an unbounded
  field is an unbounded chain, and a loop can bury the records you came for
- **keep only known fields** — an unrecognised key is something a reader might
  believe, so it goes rather than riding along
- **strip control characters** — the chain is line-delimited JSON, and a
  newline inside a value is how one record becomes two
- **stamp provenance last**, so `asserted_by: "sandbox"` overwrites rather than
  merges. You should never have to guess which records the subject of the
  investigation wrote about itself
- **don't follow symlinks** — the agent owns that directory's contents, so it
  can swap the audit file for a link to something it isn't supposed to reach.
  Opened `O_NOFOLLOW`, with the file type checked on the descriptor so there's
  no gap between the check and the read

The record *type* is set by the host, never taken from the file. An agent
writing `{"event": "sandbox.attested", ...}` gets a `decision` record, because
`verify` keys controls off the host-set type.

## What we trust, and what that costs you

The host process is trusted. It writes the chain, holds the records, seals the
bundle.

Which means: **a bundle currently proves things about the agent, not about the
operator.** And while it's unsigned, it doesn't strictly prove anything about
either, since whoever can edit the chain can recompute it.

This is the boundary most worth moving, and it's worth being precise about the
two different things signing could buy:

- Signing with a key the operator holds makes a bundle evidence *against the
  agent*. That's issues #2–#4.
- Making it evidence against the *operator* requires a key the operator can't
  wield alone. Different problem, and the output should never blur the two.

The guard is already a separate trust domain — own container, own network, own
directory — but not yet a separate *signer*, so in principle the host could
drop a guard record. That's #6.

## Things that are weaker than they sound

**The agent no longer runs as root** — the driver passes `--user` and the
bundle records the uid it read back from inside the container:

```text
runs_as_non_root: True (runtime_readback) — the agent process runs as uid 501
```

It mirrors your own uid by default, because `/work` is a bind mount you own and
a fixed unprivileged uid couldn't write the files the agent exists to produce.
If `wl-enclave` itself is running as root, we fall back to uid 65532 rather
than handing the container uid 0 — but then bind-mount ownership is something
whoever set that up needs to think about.

**`/work/policies` and `/policy` are the same inodes**, and the first is
writable. We take the governing digest once, at open, so tampering *within* a
run isn't visible yet — only tampering that affects the next run. Issue #18.
