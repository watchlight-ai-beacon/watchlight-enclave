"""Runtime drivers — one isolation boundary behind one protocol.

:class:`RuntimeDriver` is the whole seam between Enclave and whatever isolates
the agent. Supporting a new isolation runtime means adding one module here and
nothing else; if a change is needed anywhere outside this package, the seam is
in the wrong place.

The protocol deliberately includes :meth:`RuntimeDriver.attest`. A driver must
be able to report, *reading back from the runtime rather than from our own
request*, what constraints the sandbox is actually under. That read-back is what
makes the isolation half of an evidence bundle worth anything.
"""

from __future__ import annotations

import os

import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

__all__ = [
    "Egress",
    "Mount",
    "SandboxSpec",
    "Sandbox",
    "RuntimeDriver",
    "DriverError",
    "get_driver",
]


class DriverError(Exception):
    """The runtime refused an operation, or is not usable on this machine."""


#: Used only when wl-enclave itself runs as root, where mirroring the caller
#: would hand the container uid 0. Matches the guard image's declared user.
NONROOT_FALLBACK_UID = 65532


def nonroot_user() -> str:
    """The ``uid:gid`` a container runs as. Never ``0``.

    Shared by the sandbox and the guard because they face the same problem
    from opposite ends. Both must run unprivileged, and both write to a
    directory bind-mounted from the host: the sandbox its workspace, the guard
    its record file. On a bind mount the host's ownership is what the kernel
    enforces, so a container running as a *fixed* unprivileged uid cannot
    write files the invoking user owns — which is every file that matters here.

    Mirroring the caller resolves it: unprivileged and able to write are the
    same choice. The guard image still declares ``USER 65532`` so it is
    unprivileged if run by hand, and this overrides it with a uid that can
    actually reach the record file.

    When wl-enclave is itself root, mirroring would put uid 0 in the
    container, so a fixed unprivileged uid is used instead and bind-mount
    ownership becomes the operator's problem.
    """
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        return f"{NONROOT_FALLBACK_UID}:{NONROOT_FALLBACK_UID}"
    return f"{uid}:{gid}"

@dataclass(frozen=True)
class Mount:
    """One entry in a sandbox's filesystem, exposed or hidden.

    Both kinds live in the same ordered list because they are the same
    decision: what the sandbox can see at a path. They were two lists, and the
    cost of that showed up twice. The driver validated the relationship between
    them, so every other driver would have had to reimplement that check or
    silently omit it; and the caller had to derive a masked path from a mount
    target it held separately, which is how a mask could name somewhere no
    mount reached.

    ``source is None`` is the discriminant: a mask has nothing behind it to
    name. Use :meth:`bind` and :meth:`mask` rather than the constructor, so a
    mask with a source is not a thing that can be written.
    """

    target: str
    source: Optional[Path] = None
    read_only: bool = True

    @property
    def masked(self) -> bool:
        """True when this entry hides a path rather than exposing one."""
        return self.source is None

    @classmethod
    def bind(cls, source: Path, target: str, read_only: bool = True) -> "Mount":
        """Expose a host path inside the sandbox."""
        return cls(target=target, source=Path(source), read_only=read_only)

    @classmethod
    def mask(cls, target: str) -> "Mount":
        """Cover a path with an empty writable filesystem.

        Used to keep a run's own evidence out of reach of a workspace mount
        that would otherwise contain it. A mask is always writable: the point
        is that the sandbox sees an ordinary empty directory rather than a
        permission error it could mistake for a bug in its own code.
        """
        return cls(target=target, source=None, read_only=False)


@dataclass(frozen=True)
class Egress:
    """How a sandbox may reach the network, if at all.

    A bare network name does not carry the intent. ``"none"`` and
    ``"wl-enclave-<run>"`` are both just strings, and nothing in a string says
    whether a named network is an internal one whose only route out is a guard
    or an ordinary bridge with a default route to the internet. A driver handed
    only the name cannot tell the difference, so it cannot refuse the wrong one
    and cannot attest the right one as anything stronger than "a network was
    attached".

    Stating the intent separately means the driver is checking the sandbox
    against what was *asked for* rather than reporting what it happens to find.
    """

    #: Runtime network to attach, or ``"none"`` for no network at all.
    network: str = "none"
    #: True when this network's only route out is an allowlisting guard. The
    #: driver is expected to verify that claim, not take it.
    mediated: bool = False
    #: ``host:port`` of the guard, recorded so a reviewer can tell which
    #: endpoint the sandbox was pointed at.
    endpoint: str = ""
    #: The allowlist the guard was given. Carried here because it is part of
    #: what the run was permitted to do, and a bundle that states the topology
    #: without the policy describes only half the boundary.
    allow: tuple[str, ...] = ()

    @classmethod
    def none(cls) -> "Egress":
        """No network. The default, and the only thing that needs no proof."""
        return cls()

    @classmethod
    def mediated_by(
        cls, network: str, endpoint: str, allow: list[str]
    ) -> "Egress":
        """A network whose only route out is the given guard."""
        return cls(
            network=network,
            mediated=True,
            endpoint=endpoint,
            allow=tuple(sorted(allow)),
        )


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
    #: Binds and masks together, in the order a reader should understand them.
    #: Argv order does not decide which wins — the daemon sorts mount points by
    #: destination path length — so this list is for the reader and for the
    #: coherence check below, not for the runtime.
    mounts: list[Mount] = field(default_factory=list)
    #: How this sandbox may reach the network. Replaces a bare network name,
    #: which could not distinguish an internal guard-only network from a
    #: bridge — see :class:`Egress`.
    egress: Egress = field(default_factory=Egress)
    memory_bytes: int = 2 * 1024**3
    cpus: float = 2.0
    pids: int = 512

    def __post_init__(self) -> None:
        for problem in self.incoherent_mounts():
            raise DriverError(problem)

    def incoherent_mounts(self) -> list[str]:
        """Ways this spec's mounts contradict each other.

        Checked on the spec rather than in a driver because it is a fact about
        what was asked for, not about how one runtime implements it: a second
        driver must not be able to omit the check by forgetting it existed.

        The invariant is nesting. A mask covers a path *inside* a bind, so a
        mask that is not strictly below some bind target collides with a mount
        instead of covering it — and the collision is silent, because the
        runtime reports the mask as requested either way.
        """
        problems: list[str] = []
        if self.egress.mediated and self.egress.network in ("", "none"):
            problems.append(
                "egress claims to be guard-mediated but names no network; "
                "a mediated route has to run through something"
            )
        if not self.egress.mediated and self.egress.endpoint:
            problems.append(
                f"egress names an endpoint ({self.egress.endpoint}) but is not "
                f"marked mediated; a sandbox pointed at a guard it is not "
                f"required to go through would be attested as if it were"
            )
        binds = [m for m in self.mounts if not m.masked]
        bind_targets = [posixpath.normpath(m.target) for m in binds]

        for mount in self.mounts:
            normalised = posixpath.normpath(mount.target)
            if not posixpath.isabs(normalised):
                problems.append(
                    f"mount target {mount.target!r} is not absolute"
                )
                continue
            # A path that changes under normalisation would be checked as one
            # location and mounted as another, since the runtime normalises
            # the destination itself.
            if normalised != mount.target.rstrip("/") or not mount.target:
                problems.append(
                    f"mount target {mount.target!r} is not normalised "
                    f"(it resolves to {normalised!r})"
                )
                continue
            if mount.masked and not any(
                normalised.startswith(target + "/") for target in bind_targets
            ):
                problems.append(
                    f"masked path {mount.target!r} is not strictly below a "
                    f"bind target ({', '.join(bind_targets) or 'none'}); it "
                    f"would collide with a mount instead of covering it"
                )
        return problems

    def host_path_behind(self, mask: Mount) -> Optional[Path]:
        """The host directory a masked path resolves to, or ``None``.

        What a mask hides is a real directory on the host, and testing that the
        mask holds means reading something planted there. The longest matching
        bind target is the one the mask is nested in.
        """
        if not mask.masked:
            return None
        target = posixpath.normpath(mask.target)
        best: Optional[tuple[int, Path, str]] = None
        for mount in self.mounts:
            if mount.masked or mount.source is None:
                continue
            bind = posixpath.normpath(mount.target)
            if target.startswith(bind + "/") and (best is None or len(bind) > best[0]):
                best = (len(bind), mount.source, bind)
        if best is None:
            return None
        _, source, bind = best
        return Path(source).resolve() / posixpath.relpath(target, bind)


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

    Raises :class:`DriverError` naming what is available, so a typo in
    ``runtime:`` is self-correcting.
    """
    if name in ("docker", "podman"):
        from .docker import DockerDriver

        return DockerDriver(binary=name)
    if name == "openshell":
        raise DriverError(
            "the openshell driver is not available in this build; use runtime: docker"
        )
    raise DriverError(f"no driver named {name!r} (have: docker, podman)")
