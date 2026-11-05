# Egress: what the guard sees

## The setup

```text
  SANDBOX                                    EGRESS GUARD
  joined to ONE internal network   ────▶     joined to that network
  no route out except the guard              AND an egress network
  HTTPS_PROXY points at the guard                    │
        │                                            ▼
        └── CONNECT ──────────────────────▶   allowlist decision
                                                     │
                                          ┌──────────┴──────────┐
                                          ▼                     ▼
                                      upstream          egress.attempt
```

**The internal network is the control. The proxy variables are a
convenience.** This ordering is the whole thing: an agent that ignores
`HTTPS_PROXY` finds no route out, not a bypass. If the variables were the
control, an agent could simply not read them.

The guard starts before the sandbox, because a sandbox that starts first has a
window where nobody is watching.

## Plaintext HTTP is refused, not forwarded

Forwarding it would mean parsing and rewriting attacker-controlled requests for
no evidentiary gain — an agent that wants to be governed can use TLS. Refusing
is the smaller attack surface.

**Nothing inside the tunnel is inspected.** A record says *where* and
*whether*, never *what*: no request bodies, no headers, no credentials.

We could terminate TLS and get finer policy (method, path) out of it. We'd also
be holding the agent's secrets in the guard, which makes the guard a far more
attractive target and makes the "we never see your traffic" claim impossible.
Not worth it.

## Address validation

The allowlist matches a **hostname**. A hostname is not where traffic goes. So:

1. Match host:port against the allowlist. Wildcards only as a leading `*.`,
   and they don't match the apex.
2. **Resolve once.** Validate the resolved addresses. Dial the validated
   `SocketAddr` — *not the hostname again*. Re-resolving between the check and
   the connection is DNS rebinding, and avoiding it is why this is three steps
   instead of two.
3. Record the address we actually dialled. If you're joining this bundle
   against a firewall or netflow log, the IP is the only field you have in
   common — and for a rebinding attempt, the IP *is* the finding.

What gets refused, and why:

| Blocked | Reason |
|---|---|
| loopback, private, link-local | your host and its neighbours aren't the internet |
| `169.254.169.254` | cloud instance metadata — credentials |
| all of `0.0.0.0/8` | "this host", in several spellings |
| IPv4-mapped IPv6 | judged by v4 rules, or every v4 rule is bypassable by spelling |
| NAT64 `64:ff9b::/96`, `::/96` | same, with the embedded v4 extracted |
| 6to4 `2002::/16` | same |
| `2001::/23`, `fec0::/10` | not routable destinations |
| anything outside `2000::/3` | default-deny for IPv6 |

Order matters here: loopback, unspecified, and multicast are checked **before**
the embedded-v4 branches. `::1` has six zero segments, so reading it as
embedded-v4 gives you `0.0.0.1` — which would sail through as a public
address. There's a test named after that trap.

## Recording comes first

**If the guard can't record an attempt, it refuses the connection.**

This inverts the usual instinct that logging should never fail the request it
describes. But for a product whose claim is that a bundle can't understate what
happened, forwarding traffic you couldn't record is strictly worse than
refusing it. A refused connection is a denial of service the agent can see and
the bundle explains. An unrecorded one is a silent hole.

That has to hold for *every* way a write can fail. It originally only held for
budget exhaustion: a full or failing evidence file returned success, so the
caller forwarded the tunnel, and a policy-allowed egress crossed the boundary
with no record of it — in a bundle that still verified as complete. The write
result is now the return value:

```rust
if writeln!(state.file, "{record}").is_err() || state.file.flush().is_err() {
    state.write_errors += 1;
    return false;
}
```

## Two laundering attacks that shaped this

**Record flooding.** Cheap, payload-free connections shared one budget with
expensive evidence. Fill the file with noise, *then* tunnel to an allowlisted
host, and you leave no trace — while the bundle reads "attested, no attempts".
Saturation notes now get their own allowance and are aggregated at most once
per second, so cheap noise can't spend the budget that real records need.

**Unparseable requests.** A request head that timed out, overran its size
bound, or carried no request line got a status code and left no trace at all.
So a bundle couldn't distinguish "no malformed requests" from "ten thousand of
them". These are now recorded as `egress.malformed`, and they claim **no
host** — because none was parsed. Guessing one would put an attacker-chosen
string in the field you read as a destination.

## What the records cover, and what they can't

`egress.attested` carries `records_cover` and `blocked_not_recorded`, so the
bundle states its own coverage instead of letting you infer it:

```text
wl-enclave: egress   attested: the guard was the sandbox's only route
wl-enclave:          records cover http_connect only; other traffic was
wl-enclave:          blocked, not recorded
```

**Covered:** every HTTP CONNECT attempt, allowed or refused, with destination,
reason, resolved address, and bytes each way.

**Not covered:** anything that doesn't speak CONNECT. A raw socket to an
arbitrary port gets refused — there's no route — but the guard never sees it,
so it shows up as a failed connection inside the agent rather than a line in
your bundle. **Blocked, but not described.**

This is the one place where containment and observation pull against each
other, and it's an artifact of *where* we enforce rather than something
fundamental. The guard records what passes *through* it. An enforcement point
that sees all traffic — a host-side packet boundary, or syscall mediation woken
inside `connect(2)` — would record every attempt including ones with no route,
without relaxing the topology at all. Issues #12 and #14.

## Liveness and the closing tally

The guard is a container, and containers die. If it isn't running at the end of
the run we record `egress.guard_stopped` and the bundle reads `INCOMPLETE` —
attempts made after it died are *absent*, not denied.

That's a witnessing failure, not a containment one. On an internal network, a
dead guard means the sandbox could reach nothing.

We **drain** the guard before reading its records. It runs as PID 1 so it
receives SIGTERM and writes a closing account: the true suppression total, the
refusal count, the write-error count. We used to remove it with SIGKILL, which
meant that account never got written — and the inline suppression note is
latched at whatever the count was when the cap was first crossed. A run that
dropped ten thousand records reported one.
