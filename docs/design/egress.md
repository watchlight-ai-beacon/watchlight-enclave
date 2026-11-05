# Egress

## Topology

```text
   SANDBOX                                 EGRESS GUARD
   joined to ONE internal network          joined to that network
   no route out except the guard           AND an egress network
   HTTPS_PROXY -> the guard                       |
         |                                        v
         +--> CONNECT ------------------->  allowlist decision
                                                  |
                                         +--------+--------+
                                         |                 |
                                    upstream         egress.attempt
```

The internal network is the enforcement point. Proxy environment variables are
a *convenience* for the agent, not a control: an agent that ignores them finds
no route rather than a bypass. That ordering matters — if the variables were
the control, an agent could simply not read them.

The guard is started before the sandbox. A sandbox that starts first has a
window with no witness.

## Why plaintext HTTP is refused rather than forwarded

Forwarding it would mean parsing and rewriting attacker-controlled requests for
no evidentiary gain, since an agent that wants to be governed can use TLS.
Refusing is the smaller attack surface.

Nothing inside the tunnel is inspected. A record says **where** and **whether**,
never **what** — no request body, no headers, no credentials. Terminating TLS
would buy finer policy (method, path) at the cost of holding the agent's
secrets in the guard, which would make the guard a far more attractive target
and make this claim impossible.

## Address validation

The allowlist decides on a **hostname**, and a hostname is not where traffic
goes. So:

1. Match the host:port against the allowlist. A wildcard is accepted only as a
   leading `*.`, and it does not match the apex.
2. **Resolve once.** Validate the resolved addresses. Dial the validated
   `SocketAddr` — not the hostname again. Re-resolving between the check and
   the connection is DNS rebinding, and it is the whole reason this is three
   steps rather than two.
3. Record the address actually dialled. An investigator joining this bundle
   against a firewall or netflow log has only the address in common, and for a
   rebinding attempt the address *is* the finding.

Refused address classes, with the reasoning:

| Class | Why |
|---|---|
| loopback, private, link-local | the host and its neighbours are not the internet |
| `169.254.169.254` | cloud instance metadata — credentials |
| `0.0.0.0/8` (all of it, not just `0.0.0.0`) | "this host" in several spellings |
| IPv4-mapped IPv6 | judged by v4 rules, or every v4 rule is bypassable by spelling |
| NAT64 `64:ff9b::/96`, IPv4-compatible `::/96` | same, with the embedded v4 extracted |
| 6to4 `2002::/16` | same |
| `2001::/23` IETF Protocol Assignments, `fec0::/10` | not routable destinations |
| anything outside `2000::/3` | default-deny for IPv6 |

Loopback, unspecified and multicast are decided **before** the embedded-v4
branches. `::1` has six zero segments, so an embedded-v4 reading maps it to
`0.0.0.1` — which would allow loopback. A test is named for that trap.

## Recording is a precondition, not a side effect

If an attempt cannot be recorded, the guard **refuses the connection**. This
inverts the more usual judgement that logging must never fail the request it
describes: for a product whose claim is that a bundle cannot understate what
happened, forwarding traffic that could not be recorded is the worse failure. A
refused connection is a denial of service the agent can see and the bundle
explains; an unrecorded one is a silent hole.

That has to hold for **every** way a write can fail, not just the budget. It
originally held only for budget exhaustion — a failing or full evidence file
returned success, so the caller forwarded the tunnel and a policy-allowed
egress crossed with no record of it in a bundle that verified as complete. The
write result is now the return value.

Two separate laundering attacks shaped this:

- **Record flood.** Cheap payload-free connects shared one budget with
  expensive evidence. Fill the file with noise, then tunnel to an allowlisted
  host and leave no trace, while the bundle read "attested, no attempts".
  Saturation notes now have their own allowance and are aggregated at most once
  per second, so noise cannot spend the budget that real records need.
- **Unparseable requests.** A head that timed out, overran its size bound, or
  carried no request line got a status code and left no trace, so the bundle
  could not distinguish "no malformed requests" from "ten thousand of them".
  These are now recorded, and claim **no host**, because none was parsed —
  guessing one would put an attacker-chosen string in the field a reviewer
  reads as a destination.

## What the records cover, and what they cannot

`egress.attested` carries `records_cover` and `blocked_not_recorded`, so the
bundle states its own coverage rather than leaving a reader to infer it.

**Covered:** every HTTP CONNECT attempt, allowed or refused, with destination,
reason, resolved address, and bytes each way.

**Not covered:** anything that does not speak CONNECT. A raw socket to an
arbitrary port is refused — there is no route — but the guard never sees it, so
it appears as a failed connection inside the agent rather than a line in the
bundle. **Blocked, but not described.**

This is the one place where containment and observation are in tension, and the
tension is an artefact of the enforcement point rather than something
fundamental: the guard records what passes *through* it. An enforcement point
that sees all traffic — a host-side packet boundary, or syscall-level mediation
woken inside `connect(2)` — would record every attempt including ones with no
route, without relaxing the topology. Tracked in #12.

## Guard liveness and its closing account

The guard is a container; containers die. If it is not running at the end of
the run, `egress.guard_stopped` is recorded and the bundle reads `INCOMPLETE` —
attempts made after it died are *absent*, not denied. That is a witnessing
failure, not a containment one: on an internal network a dead guard means the
sandbox could reach nothing.

The guard is **drained** before its records are read. It is built as PID 1 to
receive SIGTERM and write a closing account — the true suppression total, the
refusal count, the write-error count. Removing it with SIGKILL instead meant
that account was never written, while the inline suppression note is latched at
the count when the cap was first crossed. A run that dropped ten thousand
records reported one.
