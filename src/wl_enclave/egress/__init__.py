"""Egress guards — who the sandbox may talk to, and a record of every attempt.

The sandbox's isolation settings establish what it is *constrained to*. They do
not establish what it *tried*. With no network interface a refused connection
leaves no trace, and the agent's own failed ``connect()`` is not testimony
anyone should accept about itself. Closing that gap needs something in the path.

:class:`EgressGuard` is that seam, and it owns the record schema rather than
delegating it. Keeping the schema here means a guard can be replaced without
changing what a bundle looks like, so a verifier written against one guard
still reads a bundle produced by another.

:class:`LocalEgressGuard` is the implementation that ships: a CONNECT proxy
with an allowlist, no TLS interception and no credential injection. It is
deliberately small, because everything it does is in the path of the agent's
traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

__all__ = [
    "EGRESS_ATTESTED",
    "entry_problem",
    "EGRESS_UNRECOGNISED",
    "GUARD_RECORD_TYPES",
    "EGRESS_RECORD",
    "Allowlist",
    "EgressEndpoint",
    "EgressGuard",
    "GuardError",
    "get_guard",
]

#: The record type a guard writes once per run, stating whether the runtime
#: confirms it was the sandbox's only route.
EGRESS_ATTESTED = "egress.attested"

#: The record type every guard appends to the evidence chain. One per attempt.
#:
#: ``{"host", "port", "verdict", "reason", "protocol", "ts"}``, plus
#: ``resolved_ip`` when an address was actually chosen — ``verdict`` is
#: ``"allow"`` or ``"deny"``. No request body, no headers, no credentials: a
#: record says *where* and *whether*, never *what*.
#:
#: ``resolved_ip`` is present only when the guard picked an address, so its
#: absence is information too. The hostname is what the allowlist decides on
#: and it is not where the traffic went: a name can resolve differently between
#: the decision and the next lookup, and an investigator joining this bundle
#: against a firewall or netflow log has only the address in common.
EGRESS_RECORD = "egress.attempt"

#: Every chain record type a guard is permitted to contribute.
#:
#: A guard's records arrive as data, so the type they land under is chosen by
#: the orchestrator against this set and never read out of the record itself. A
#: record that could name its own type could name ``decision`` or
#: ``sandbox.attested`` and forge a record belonging to a layer that never ran
#: — inside a chain that would then hash the forgery faithfully.
GUARD_RECORD_TYPES = frozenset({
    "egress.attempt",
    "egress.malformed",
    "egress.tunnel",
    "egress.tunnel_progress",
    "egress.records_suppressed",
    "egress.saturated",
})

#: Where a record whose declared type is not in :data:`GUARD_RECORD_TYPES` is
#: put. It is kept rather than dropped: an unrecognised record is itself worth
#: seeing, and discarding it would let a writer erase evidence by malforming it.
EGRESS_UNRECOGNISED = "egress.unrecognised"


#: Characters a hostname label sequence may contain, once any wildcard is off.
#: Anchored with fullmatch at the call site: ``$`` also matches before a
#: trailing newline, so "evil.com\n" read as a valid hostname.
_LABELS = re.compile(r"[A-Za-z0-9._-]+")


def entry_problem(entry: str) -> Optional[str]:
    """Why ``entry`` is not a usable ``host:port`` rule, or ``None`` if it is.

    One function, used by both the configuration loader and the guard, because
    two validators drift and the drift is a security bug rather than an
    inconvenience: the loader accepting what the guard refuses means ``doctor``
    passes a configuration that produces a guard which exits on startup, and a
    run whose bundle then reads "attested, no attempts" — the shape of a clean
    run. The rules here are the rules the Rust matcher enforces.
    """
    if not isinstance(entry, str) or ":" not in entry:
        return "must be host:port (e.g. api.anthropic.com:443)"
    host, _, port_text = entry.rpartition(":")
    if not host:
        return "has no host"
    # str.isdigit() accepts any Unicode decimal, including "\u00b2", which
    # int() then refuses with a ValueError that escaped as a traceback out of
    # `doctor`; and "\u0664\u0664\u0663", which int() happily reads as 443
    # while the guard's u16 parser refuses it. ASCII only, so the two agree
    # and neither crashes.
    if not port_text or not all("0" <= ch <= "9" for ch in port_text):
        return "has a non-numeric port"
    port = int(port_text)
    # Matched to the guard, which parses the port as a u16 and refuses zero.
    if not 1 <= port <= 65535:
        return f"has port {port}, which is outside 1-65535"
    if host.startswith("*."):
        rest = host[2:]
        if not rest:
            return "has no domain after the wildcard"
        if "*" in rest:
            return 'may only use a wildcard as a leading "*."'
        return None if _LABELS.fullmatch(rest) else "has an invalid hostname"
    if "*" in host:
        # The bug this closes: "*openai.com" once stripped to the dotless
        # suffix "openai.com", so a suffix match admitted "evilopenai.com".
        return 'may only use a wildcard as a leading "*."'
    return None if _LABELS.fullmatch(host) else "has an invalid hostname"


class GuardError(Exception):
    """The guard could not be started, or is unusable on this machine."""


@dataclass(frozen=True)
class EgressEndpoint:
    """Where the sandbox should send its traffic, and how to tell it so."""

    host: str
    port: int

    @property
    def env(self) -> dict[str, str]:
        """Proxy variables for the sandbox.

        Both cases are set because libraries disagree about which they read,
        and ``NO_PROXY`` is left unset on purpose: an exemption here would be a
        hole in the allowlist.
        """
        url = f"http://{self.host}:{self.port}"
        return {
            "HTTP_PROXY": url, "http_proxy": url,
            "HTTPS_PROXY": url, "https_proxy": url,
        }


class Allowlist:
    """The hosts and ports a sandbox may reach. Everything else is refused.

    Entries are ``host:port``. A leading ``*.`` matches one or more labels, so
    ``*.anthropic.com:443`` admits ``api.anthropic.com:443`` but not
    ``anthropic.com:443`` — a wildcard should not quietly widen to the apex.
    """

    def __init__(self, entries: list[str]) -> None:
        self.entries = list(entries)
        self._rules: list[tuple[str, int]] = []
        for entry in self.entries:
            # The same validator the configuration loader uses, and the same
            # rules the guard enforces. This class previously had a regex of
            # its own that was laxer than both, so Allowlist(["*openai.com:443"])
            # and Allowlist(["host:0"]) constructed successfully — the exact
            # loader/guard drift entry_problem exists to prevent, in the public
            # type that documents the schema.
            problem = entry_problem(entry)
            if problem:
                raise GuardError(f"egress.allow: {entry!r} {problem}")
            host, _, port = entry.rpartition(":")
            self._rules.append((host.lower(), int(port)))

    def __bool__(self) -> bool:
        return bool(self._rules)

    # No permits() here on purpose. Enforcement lives in the guard, which is
    # the only thing in the request path; a second matcher in Python would be a
    # third set of semantics that nothing consults and that the next reader
    # would reasonably mistake for the authority. The one it had disagreed with
    # the guard: fnmatch's "*" matches the empty string, so ".openai.com"
    # matched "*.openai.com" here and was refused there.


@runtime_checkable
class EgressGuard(Protocol):
    """Mediates the sandbox's outbound traffic and records every attempt."""

    name: str

    def preflight(self) -> list[str]:
        """Problems that would stop a run; empty means ready. Never raises."""
        ...

    def build(self) -> dict:
        """Which guard build is about to write records, read back from the runtime.

        Part of the protocol rather than a Docker detail, because the guard is
        the witness whose records the agent cannot influence. "Which build
        produced this evidence" is a question a reviewer is entitled to ask of
        any guard, and an implementation that cannot answer should return an
        empty dict rather than a plausible-looking guess.
        """
        ...

    def state(self) -> dict:
        """What the runtime says the guard is doing *now*, read back from it.

        Separate from :meth:`attest` because the two answer questions at
        different times. An attestation is taken once, when the sandbox is
        provisioned; this is asked again at the end, because a guard that
        stopped witnessing part-way through leaves a record file that is merely
        quiet. An implementation that cannot tell should return
        ``{"guard_state_unreadable": True}`` rather than imply health.
        """
        ...

    def start(self, run_id: str, allowlist: Allowlist, record_file: Path) -> EgressEndpoint:
        """Bring the guard up and return where the sandbox should send traffic.

        ``record_file`` is appended to as attempts happen, not written at the
        end: a sandbox killed mid-run must still leave behind what it tried.
        """
        ...

    def network(self) -> Optional[str]:
        """The network the sandbox must join, or ``None`` for no network.

        A guard that can only be reached — and cannot be bypassed — from a
        particular network names it here. The driver puts the sandbox on it.
        """
        ...

    def attest(self, sandbox_ref: Optional[str] = None) -> dict:
        """Report the topology **as the runtime reports it**.

        The allowlist and the records are only worth as much as the claim that
        the guard was the sandbox's one way out. Everything else here asserts
        that claim; this method is the only thing that checks it, by reading
        the network layout back out of the runtime instead of trusting what we
        asked for.

        ``route_exclusive`` is the finding that matters. When it is false the
        sandbox had some other path to the network, so proxy environment
        variables were advice the agent was free to ignore and the records are
        a lower bound on what it attempted, not an account of it. A bundle that
        is quietly incomplete is worse than one that admits the gap, so this is
        recorded either way and never inferred from configuration.
        """
        ...

    def drain(self) -> None:
        """Let the guard write its closing account, and wait for it.

        Separate from :meth:`stop` because the caller reads the record file
        between the two: a guard killed outright can still be holding counts
        that exist nowhere else, and those counts are what tell a reviewer the
        size of the file's own gap.
        """
        ...

    def stop(self) -> None:
        """Tear the guard down, leaving its records in place."""
        ...


def get_guard(name: str = "local") -> EgressGuard:
    """Return a guard by name."""
    if name == "local":
        from .local import LocalEgressGuard

        return LocalEgressGuard()
    raise GuardError(f"no egress guard named {name!r} (have: local)")
