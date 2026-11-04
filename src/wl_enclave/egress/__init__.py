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

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

__all__ = [
    "EGRESS_ATTESTED",
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
#: ``{"host", "port", "verdict", "reason", "protocol", "ts"}`` — ``verdict`` is
#: ``"allow"`` or ``"deny"``. No request body, no headers, no credentials: a
#: record says *where* and *whether*, never *what*.
EGRESS_RECORD = "egress.attempt"

_HOSTPORT = re.compile(r"^(?P<host>[A-Za-z0-9._*-]+):(?P<port>\d{1,5})$")


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
            m = _HOSTPORT.match(entry)
            if not m:
                raise GuardError(f"egress.allow: {entry!r} must be host:port")
            self._rules.append((m.group("host").lower(), int(m.group("port"))))

    def __bool__(self) -> bool:
        return bool(self._rules)

    def permits(self, host: str, port: int) -> tuple[bool, str]:
        """Decide one attempt, returning the verdict and the reason for it.

        The reason names the rule that matched, because a bundle that says
        "denied" without saying against what is hard for a reviewer to act on.
        """
        host = (host or "").lower().rstrip(".")
        for pattern, allowed_port in self._rules:
            if port != allowed_port:
                continue
            if pattern == host:
                return True, f"matched {pattern}:{allowed_port}"
            if pattern.startswith("*.") and fnmatch.fnmatch(host, pattern):
                # Reject the apex: "*.example.com" must not admit "example.com".
                if host != pattern[2:]:
                    return True, f"matched {pattern}:{allowed_port}"
        if not self._rules:
            return False, "no egress.allow entries; the sandbox may reach nothing"
        return False, f"{host}:{port} is not in egress.allow"


@runtime_checkable
class EgressGuard(Protocol):
    """Mediates the sandbox's outbound traffic and records every attempt."""

    name: str

    def preflight(self) -> list[str]:
        """Problems that would stop a run; empty means ready. Never raises."""
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

    def stop(self) -> None:
        """Tear the guard down, leaving its records in place."""
        ...


def get_guard(name: str = "local") -> EgressGuard:
    """Return a guard by name."""
    if name == "local":
        from .local import LocalEgressGuard

        return LocalEgressGuard()
    raise GuardError(f"no egress guard named {name!r} (have: local)")
