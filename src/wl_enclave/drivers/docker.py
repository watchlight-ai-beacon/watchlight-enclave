"""The Docker driver — the default lane, because it is already installed.

Docker ships first for one reason: *time to a governed run*. A developer who
has to install a gateway, mint mTLS certificates and edit a TOML file before
anything runs will not get to the point. ``docker`` is on the machine already,
so ``wl-enclave run`` works in minutes.

This driver also serves ``runtime: podman``, since the podman CLI is
argument-compatible for everything used here.

What it enforces, and what that proves
--------------------------------------
The sandbox gets no network by default, a read-only root, every capability
dropped, no privilege escalation, and explicit memory, CPU and PID ceilings.
:meth:`DockerDriver.attest` then reads those constraints **back out of the
runtime** rather than echoing the request, which is the only version worth
putting in an evidence bundle.

Be precise about what that evidence is. It proves what the sandbox was
*constrained to*, not every attempt it made: with no network interface, a
blocked connection leaves no record anywhere, and the agent's own failed
``connect()`` is not testimony anyone should accept about itself. Per-attempt
egress evidence needs something in the path — an allowlisting proxy, or
OpenShell's own audit stream.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from . import DriverError, Sandbox, SandboxSpec

#: Ceiling on any single docker invocation that is not expected to block.
_CALL_TIMEOUT = 60


class DockerDriver:
    """Provisions sandboxes with the Docker (or Podman) CLI."""

    def __init__(self, binary: str = "docker") -> None:
        self.name = binary
        self._bin = binary

    # -- plumbing ---------------------------------------------------------
    def _run(
        self,
        *args: str,
        timeout: Optional[int] = _CALL_TIMEOUT,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(
                [self._bin, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise DriverError(f"{self._bin} is not installed") from exc
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise DriverError(
                f"{self._bin} {args[0]} failed: "
                + (detail[-1] if detail else f"exit {proc.returncode}")
            )
        return proc

    # -- protocol ---------------------------------------------------------
    def preflight(self) -> list[str]:
        """Report what would stop a run. Never raises."""
        if shutil.which(self._bin) is None:
            return [
                f"{self._bin} is not installed or not on PATH",
                "install Docker Desktop, Colima, or Podman",
            ]
        try:
            proc = subprocess.run(
                [self._bin, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=20,
            )
        except subprocess.TimeoutExpired:
            return [f"{self._bin} did not respond within 20s — is the daemon running?"]
        except OSError as exc:
            return [f"could not run {self._bin}: {exc}"]
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip().splitlines()
            return [
                f"the {self._bin} daemon is not reachable"
                + (f": {detail[-1]}" if detail else ""),
                "start it (e.g. `colima start`, or open Docker Desktop)",
            ]
        return []

    @staticmethod
    def _reject_flaglike(label: str, value: str) -> None:
        """Refuse a value that the runtime CLI would read as a flag.

        Defence in depth: ``config`` already validates the image reference, but
        this driver must not depend on having been called through it. Every
        argv element that is not a literal we wrote is checked here, because
        ``docker run`` parses flags until the image and an injected
        ``--privileged`` or ``--network=host`` would silently undo every
        isolation flag set below.
        """
        if not value or value.startswith("-"):
            raise DriverError(
                f"{label}: {value!r} would be read as a command-line flag by "
                f"{'docker' if value else 'the runtime'}, so it is refused"
            )

    def provision(self, spec: SandboxSpec) -> Sandbox:
        """Create and start the sandbox, detached."""
        # Checked before anything is built: these are the only argv elements
        # that are not literals chosen by this module.
        self._reject_flaglike("agent.image", spec.image)
        self._reject_flaglike("sandbox name", spec.name)
        for key in spec.env:
            self._reject_flaglike("env name", key)

        args: list[str] = [
            "run",
            "--detach",
            "--name", spec.name,
            # isolation
            "--network", spec.network,
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            # ceilings
            "--pids-limit", str(spec.pids),
            "--memory", str(spec.memory_bytes),
            "--cpus", str(spec.cpus),
            "--workdir", spec.workdir,
        ]
        for mount in spec.mounts:
            ro = ",readonly" if mount.read_only else ""
            args += [
                "--mount",
                f"type=bind,src={mount.source.resolve()},dst={mount.target}{ro}",
            ]
        for key, value in sorted(spec.env.items()):
            args += ["--env", f"{key}={value}"]
        args += [spec.image, *spec.command]

        proc = self._run(*args)
        container_id = proc.stdout.strip()
        if not container_id:
            raise DriverError(f"{self._bin} run returned no container id")
        return Sandbox(id=container_id, name=spec.name, driver=self.name)

    def attest(self, sandbox: Sandbox) -> dict:
        """Read the sandbox's actual constraints back out of the runtime.

        Deliberately not a copy of :class:`SandboxSpec`. A bundle that repeats
        what we asked for proves nothing; this reports what the runtime says is
        in force, and records the runtime's own version alongside it.
        """
        proc = self._run("inspect", sandbox.id)
        try:
            inspected = json.loads(proc.stdout)[0]
        except (json.JSONDecodeError, IndexError, KeyError) as exc:
            raise DriverError(f"could not parse {self._bin} inspect output") from exc

        host = inspected.get("HostConfig", {}) or {}
        state = inspected.get("State", {}) or {}
        version = self._run(
            "version", "--format", "{{.Server.Version}}", check=False
        ).stdout.strip()

        return {
            "driver": self.name,
            "runtime_version": version or "unknown",
            "container_id": inspected.get("Id", sandbox.id),
            "image": (inspected.get("Config", {}) or {}).get("Image"),
            "started_at": state.get("StartedAt"),
            "constraints": {
                "network_mode": host.get("NetworkMode"),
                "read_only_root": bool(host.get("ReadonlyRootfs")),
                "cap_drop": host.get("CapDrop") or [],
                "cap_add": host.get("CapAdd") or [],
                "security_opt": host.get("SecurityOpt") or [],
                "privileged": bool(host.get("Privileged")),
                "pids_limit": host.get("PidsLimit"),
                "memory_bytes": host.get("Memory"),
                "nano_cpus": host.get("NanoCpus"),
            },
            "mounts": [
                {
                    "source": m.get("Source"),
                    "destination": m.get("Destination"),
                    "read_write": m.get("RW"),
                }
                for m in (inspected.get("Mounts") or [])
            ],
        }

    def wait(self, sandbox: Sandbox, timeout_seconds: int) -> Optional[int]:
        """Block until the sandbox exits; ``None`` if it outlived the timeout."""
        try:
            proc = self._run("wait", sandbox.id, timeout=timeout_seconds, check=False)
        except subprocess.TimeoutExpired:
            return None
        out = proc.stdout.strip()
        try:
            return int(out.splitlines()[-1])
        except (ValueError, IndexError):
            return None

    def logs(self, sandbox: Sandbox) -> str:
        """Everything the sandbox wrote, stdout and stderr interleaved."""
        proc = self._run("logs", sandbox.id, check=False)
        return (proc.stdout or "") + (proc.stderr or "")

    def quarantine(self, sandbox: Sandbox) -> None:
        """SIGKILL the sandbox. No grace period, no cooperation required."""
        self._run("kill", "--signal", "KILL", sandbox.id, check=False)

    def teardown(self, sandbox: Sandbox) -> None:
        """Remove the sandbox, whether or not it is still running."""
        self._run("rm", "--force", "--volumes", sandbox.id, check=False)

    # -- beyond the protocol ---------------------------------------------
    def build_image(self, context: Path, dockerfile: Path, tag: str) -> str:
        """Build an image for the sandbox, returning the tag.

        Not part of :class:`~wl_enclave.drivers.RuntimeDriver`: a driver whose
        runtime takes a prebuilt image has nothing to implement. Callers probe
        for it with :func:`hasattr`.
        """
        self._reject_flaglike("image tag", tag)
        self._run(
            "build",
            "--file", str(dockerfile),
            "--tag", tag,
            str(context),
            timeout=600,
        )
        return tag
