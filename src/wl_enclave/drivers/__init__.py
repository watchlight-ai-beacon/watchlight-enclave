"""Runtime drivers — one isolation boundary behind one protocol.

:class:`RuntimeDriver` is the whole seam between Enclave and whatever isolates
the agent. Docker ships first because it is already on the developer's machine;
Podman and NVIDIA OpenShell follow behind the same protocol. A new sandbox needs
one module here and nothing else.

The protocol deliberately includes :meth:`RuntimeDriver.attest`. A driver must
be able to report, *reading back from the runtime rather than from our own
request*, what constraints the sandbox is actually under. That read-back is what
makes the isolation half of an evidence bundle worth anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

__all__ = [
    "Mount",
    "SandboxSpec",
    "Sandbox",
    "RuntimeDriver",
    "DriverError",
    "get_driver",
]


class DriverError(Exception):
    """The runtime refused an operation, or is not usable on this machine."""


@dataclass(frozen=True)
class Mount:
    """A host path exposed inside the sandbox."""

    source: Path
    target: str
    read_only: bool = True


@dataclass(frozen=True)
class SandboxSpec:
    """What to provision. Driver-neutral by construction.

    ``network`` is ``"none"`` for total isolation, or the name of a network the
    driver has prepared whose only route out is an allowlisting proxy.
    """

    name: str
    image: str
    command: list[str]
    workdir: str = "/work"
    env: dict[str, str] = field(default_factory=dict)
    mounts: list[Mount] = field(default_factory=list)
    network: str = "none"
    memory_bytes: int = 2 * 1024**3
    cpus: float = 2.0
    pids: int = 512


@dataclass
class Sandbox:
    """A provisioned sandbox, as the driver that made it refers to it."""

    id: str
    name: str
    driver: str


@runtime_checkable
class RuntimeDriver(Protocol):
    """The seam. Everything Enclave needs from an isolation runtime."""

    #: Name as it appears under ``runtime:`` in ``enclave.yaml``.
    name: str

    def preflight(self) -> list[str]:
        """Return the problems that would stop a run; empty means ready.

        Never raises. ``wl-enclave doctor`` prints whatever comes back.
        """
        ...

    def provision(self, spec: SandboxSpec) -> Sandbox:
        """Create and start the sandbox. Raises :class:`DriverError`."""
        ...

    def attest(self, sandbox: Sandbox) -> dict:
        """Report the sandbox's constraints **as the runtime reports them**.

        Read back from the runtime, never echoed from :class:`SandboxSpec`: a
        bundle that merely repeats what we asked for proves nothing.
        """
        ...

    def wait(self, sandbox: Sandbox, timeout_seconds: int) -> Optional[int]:
        """Block until exit, returning the status, or ``None`` on timeout."""
        ...

    def logs(self, sandbox: Sandbox) -> str:
        """Everything the sandbox wrote to stdout and stderr."""
        ...

    def quarantine(self, sandbox: Sandbox) -> None:
        """Kill the sandbox immediately, without waiting for it to cooperate."""
        ...

    def teardown(self, sandbox: Sandbox) -> None:
        """Remove the sandbox and anything the driver created for it."""
        ...


def get_driver(name: str) -> RuntimeDriver:
    """Return the driver named under ``runtime:``.

    Raises :class:`DriverError` naming what is available when the driver is
    unknown, or known but not built yet.
    """
    if name in ("docker", "podman"):
        from .docker import DockerDriver

        return DockerDriver(binary=name)
    if name == "openshell":
        raise DriverError(
            "the openshell driver is not in this build yet; use runtime: docker"
        )
    raise DriverError(f"no driver named {name!r} (have: docker, podman)")
