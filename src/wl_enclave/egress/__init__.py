"""Egress guards — who the sandbox may talk to, and a record of every attempt.

The sandbox's isolation settings establish what it is *constrained to*. They do
not establish what it *tried*. With no network interface a refused connection
leaves no trace, and the agent's own failed ``connect()`` is not testimony
anyone should accept about itself. Closing that gap needs something in the path.

:class:`EgressGuard` is that seam, and it owns the record schema rather than
delegating it. Two implementations are planned, and they must be
indistinguishable in the evidence bundle:

``LocalEgressGuard``
    Ships here, in the open-source lane. A CONNECT proxy with an allowlist.
    No TLS interception and no credential injection — deliberately small, so
    there is almost nothing that can drift from the other implementation.

``wl-proxy`` (reduced profile)
    The governed lane, when a control plane exists. Adds credential injection
    so a key never enters the sandbox, and TLS inspection. It is **not** usable
    here as it stands: ``apdp_endpoint`` and ``wsb_endpoint`` are required
    rather than optional, and NATS, KMS and vault PKI are compiled in
    unconditionally, so it cannot run without the fleet behind it.

A bundle produced on a laptop and one produced by a governed fleet are
therefore the same artifact at different strengths, which is the property that
makes the local lane worth having at all.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

__all__ = [
    "EGRESS_RECORD",
    "Allowlist",
    "EgressEndpoint",
    "EgressGuard",
    "GuardError",
    "get_guard",
]

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

    def stop(self) -> None:
        """Tear the guard down, leaving its records in place."""
        ...


def get_guard(name: str = "local") -> EgressGuard:
    """Return a guard by name.

    Raises :class:`GuardError` for the reduced ``wl-proxy`` profile, which is
    planned but not buildable yet (see the module docstring).
    """
    if name == "local":
        from .local import LocalEgressGuard

        return LocalEgressGuard()
    if name in ("wl-proxy", "proxy"):
        raise GuardError(
            "the wl-proxy guard needs a reduced wl-proxy profile, which does "
            "not exist yet: apdp_endpoint and wsb_endpoint are required rather "
            "than optional, and NATS, KMS and vault PKI are compiled in "
            "unconditionally. Use the local guard."
        )
    raise GuardError(f"no egress guard named {name!r} (have: local)")
