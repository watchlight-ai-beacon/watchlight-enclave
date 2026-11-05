"""The Docker driver, which also serves ``runtime: podman``.

One implementation covers both because the podman CLI is argument-compatible
for every invocation used here. If that stops being true, the divergence
belongs in a separate driver rather than in branches through this one: a
sandbox boundary that behaves differently depending on which binary is
installed is one nobody can review.

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
import posixpath
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .. import attestation
from . import DriverError, Egress, Sandbox, SandboxSpec

#: Ceiling on any single docker invocation that is not expected to block.
_CALL_TIMEOUT = 60


class DockerDriver:
    """Provisions sandboxes with the Docker (or Podman) CLI."""

    def __init__(self, binary: str = "docker") -> None:
        #: Masks declared per sandbox, keyed by container id.
        self._masks: dict[str, list[str]] = {}
        #: Canary files planted behind those masks: in-container path -> host
        #: path. Read back in attest() and removed there.
        self._canaries: dict[str, dict[str, Path]] = {}
        #: The egress intent each sandbox was provisioned with, so attest() can
        #: check the sandbox against what was asked for rather than against
        #: whatever it finds attached.
        self._egress: dict[str, Egress] = {}
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
            # The boundary. Each of these is read back out of the runtime by
            # attest() and written into the evidence chain, so removing one
            # here silently weakens what a bundle claims. --tmpfs exists
            # because a read-only root breaks most programs otherwise, and it
            # is mounted noexec so it cannot become a staging area for code
            # the image never shipped.
            "--network", spec.egress.network,
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            # Ceilings, not security boundaries. They bound the damage a
            # runaway agent does to the host it shares with everything else.
            "--pids-limit", str(spec.pids),
            "--memory", str(spec.memory_bytes),
            "--cpus", str(spec.cpus),
            "--workdir", spec.workdir,
        ]
        # One list, one pass. Argv order is not what decides which entry wins
        # — the daemon sorts mount points by destination path length, so a
        # shorter bind target is mounted before a path nested inside it
        # whatever order they arrive in. The invariant that does matter is
        # nesting, and SandboxSpec has already enforced it: a mask that is not
        # strictly below a bind target cannot be constructed.
        declared_masks: list[str] = []
        for mount in spec.mounts:
            self._reject_flaglike("mount target", mount.target)
            target = posixpath.normpath(mount.target)
            if mount.masked:
                args += ["--tmpfs", f"{target}:rw,noexec,nosuid,size=1m"]
                declared_masks.append(target)
            else:
                assert mount.source is not None  # guaranteed by Mount.bind
                ro = ",readonly" if mount.read_only else ""
                args += [
                    "--mount",
                    f"type=bind,src={mount.source.resolve()},dst={target}{ro}",
                ]

        for key, value in sorted(spec.env.items()):
            args += ["--env", f"{key}={value}"]
        args += [spec.image, *spec.command]

        proc = self._run(*args)
        container_id = proc.stdout.strip()
        if not container_id:
            raise DriverError(f"{self._bin} run returned no container id")
        # Retained so attest() can assert its own postcondition: that every
        # mask this driver applied came back. Without it the attestation can
        # only report what tmpfs mounts exist, which is not the same question.
        self._masks[container_id] = declared_masks
        self._canaries[container_id] = self._plant_canaries(spec, declared_masks)
        self._egress[container_id] = spec.egress
        return Sandbox(id=container_id, name=spec.name, driver=self.name)

    def _plant_canaries(
        self, spec: SandboxSpec, masks: list[str]
    ) -> dict[str, Path]:
        """Put a file on the host behind each mask, so the mask can be tested.

        A mask is a tmpfs mounted *over* a path inside a bind mount, so the
        host file underneath it is exactly what the sandbox must not be able to
        read. Planting one and failing to read it back is a test of the mask's
        effect; everything else available to us tests only its configuration,
        and the two came apart in practice — the daemon accepted a destination
        of ``/work/.``, reported it faithfully under ``HostConfig.Tmpfs``, and
        mounted nothing useful.

        Written after the container starts, which is fine: the tmpfs covers
        the path whenever the file underneath it appears.
        """
        planted: dict[str, Path] = {}
        by_target = {posixpath.normpath(m.target): m for m in spec.mounts}
        for mask in masks:
            mount = by_target.get(mask)
            host_path = spec.host_path_behind(mount) if mount else None
            if host_path is None:
                continue
            canary = host_path / f".wl-mask-canary-{secrets.token_hex(8)}"
            try:
                host_path.mkdir(parents=True, exist_ok=True)
                canary.write_text(
                    "If an agent can read this, the mask over its own run "
                    "directory is not in force.\n"
                )
            except OSError:
                # Not fatal. An unplanted canary means the control reports
                # "could not be confirmed", which is the honest answer.
                continue
            planted[posixpath.join(mask, canary.name)] = canary
        return planted

    def attest(self, sandbox: Sandbox) -> dict:
        """Read the sandbox's actual constraints back out of the runtime.

        Deliberately not a copy of :class:`SandboxSpec`. A bundle that repeats
        what we asked for proves nothing; this reports what the runtime says is
        in force, and records the runtime's own version alongside it.

        Every isolation setting the driver sets must appear here. A setting
        applied but not read back is indistinguishable, in the bundle, from one
        that was never applied at all.
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
                # Two fields, not one. This used to report every tmpfs key,
                # which conflated the masks that keep the run's own evidence
                # out of reach of the workspace mount with the unconditional
                # /tmp scratch — so the field read ["/tmp", "/work/runs"] and a
                # reviewer could not tell a security control from a
                # convenience. Worse, it made the mask invariant unassertable:
                # "every mask is strictly below a mount target" is false of
                # /tmp. Docker reports both under HostConfig.Tmpfs rather than
                # in Mounts, so they are invisible in a bundle that lists only
                # mounts, which is why they appear here at all.
                "masked_paths": sorted(self._masks.get(sandbox.id, [])),
                "tmpfs_paths": sorted((host.get("Tmpfs") or {}).keys()),
            },
            "mounts": [
                {
                    "source": m.get("Source"),
                    "destination": m.get("Destination"),
                    "read_write": m.get("RW"),
                }
                for m in (inspected.get("Mounts") or [])
            ],
            "controls": self._controls(sandbox, host, inspected),
        }

    def _controls(self, sandbox: Sandbox, host: dict, inspected: dict) -> dict:
        """Each isolation setting named, with how its state was established.

        The constraints block above already lists the settings. This says, for
        each one, whether it is actually in force — which is a different
        question, and the only one a reviewer can act on. A setting applied but
        not read back is indistinguishable, in a bundle, from one that was
        never applied at all.
        """
        tmpfs = set((host.get("Tmpfs") or {}).keys())
        declared = self._masks.get(sandbox.id, [])
        intent = self._egress.get(sandbox.id, Egress())
        missing = [path for path in declared if path not in tmpfs]
        cap_drop = [c.upper() for c in (host.get("CapDrop") or [])]
        security_opt = host.get("SecurityOpt") or []

        return {
            attestation.ROOTFS_READ_ONLY: attestation.control(
                bool(host.get("ReadonlyRootfs")), attestation.RUNTIME_CONFIG
            ),
            attestation.CAPABILITIES_DROPPED: attestation.control(
                "ALL" in cap_drop and not (host.get("CapAdd") or []),
                attestation.RUNTIME_CONFIG,
                ("added back: " + ", ".join(host.get("CapAdd") or []))
                if host.get("CapAdd") else "",
            ),
            attestation.NO_NEW_PRIVILEGES: attestation.control(
                any("no-new-privileges" in opt for opt in security_opt),
                attestation.RUNTIME_CONFIG,
            ),
            # The driver's postcondition. provision() refuses a mask that is
            # not strictly below a mount target; this asserts the masks it did
            # apply came back. Labelled RUNTIME_CONFIG rather than READBACK on
            # purpose: this is the daemon's record of what was requested, and
            # the daemon normalises a destination after making it. Confirming
            # the mask against the container's own mount table is the stronger
            # claim and is not made here.
            attestation.EVIDENCE_MASKED: self._mask_control(sandbox, declared, missing),
            **self._network_control(inspected, intent),
        }

    def _network_control(self, inspected: dict, intent: Egress) -> dict:
        """Whether the sandbox is on the network its spec asked for.

        Checked against the declared intent rather than against whatever is
        attached. Reporting "one network, named X" is not the same claim as
        "the network asked for, and nothing else": the second catches a
        sandbox that came up on a bridge because a network creation failed and
        something fell back, which is the case worth catching.
        """
        attached = sorted(
            ((inspected.get("NetworkSettings") or {}).get("Networks") or {}).keys()
        )
        if not intent.mediated:
            # Nothing was promised, so there is nothing to verify beyond the
            # absence the topology already guarantees.
            return {}
        if attached != [intent.network]:
            return {
                attestation.SANDBOX_ON_INTENDED_NETWORK: attestation.control(
                    False,
                    attestation.RUNTIME_CONFIG,
                    f"asked for {intent.network!r}, attached to "
                    + (", ".join(attached) or "nothing"),
                )
            }
        return {
            attestation.SANDBOX_ON_INTENDED_NETWORK: attestation.control(
                True, attestation.RUNTIME_CONFIG, f"only {intent.network}"
            )
        }

    def _mask_control(
        self, sandbox: Sandbox, declared: list[str], missing: list[str]
    ) -> dict:
        """Whether the masks are in force, observed from inside the sandbox.

        Three questions, in increasing strength, and the answer is the weakest
        one that still applies. Did the daemon record the mask? Does the
        container's own mount table show a tmpfs there? And can the sandbox
        read a file planted on the host behind it?

        The last is the one that matters, because the first two describe
        configuration and only this describes effect. They came apart in
        practice: a destination of ``/work/.`` was accepted by the daemon,
        reported faithfully under ``HostConfig.Tmpfs``, and masked nothing.
        """
        if not declared:
            return attestation.control(
                None, attestation.RUNTIME_CONFIG,
                "no masks were declared for this run",
            )
        if missing:
            return attestation.control(
                False, attestation.RUNTIME_CONFIG,
                "declared but absent from the runtime's record: "
                + ", ".join(missing),
            )

        canaries = self._canaries.get(sandbox.id) or {}
        readable = []
        unreadable = []
        for in_container, host_path in canaries.items():
            probe = self._run(
                "exec", sandbox.id, "cat", in_container, check=False, timeout=30
            )
            if probe.returncode == 0:
                readable.append(in_container)
            else:
                unreadable.append(in_container)
            try:
                host_path.unlink(missing_ok=True)
            except OSError:
                pass
        self._canaries.pop(sandbox.id, None)

        if readable:
            # The critical case. The sandbox read a file that the mask exists
            # to hide, which means it could reach its own evidence.
            return attestation.control(
                False, attestation.READBACK,
                "the sandbox read a canary planted behind the mask at "
                + ", ".join(readable),
            )

        mounts = self._run(
            "exec", sandbox.id, "cat", "/proc/mounts", check=False, timeout=30
        )
        mounted = []
        if mounts.returncode == 0:
            for line in mounts.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "tmpfs":
                    mounted.append(parts[1])

        if not unreadable:
            # No canary could be planted or read back, so nothing was actually
            # observed from inside. Say that rather than imply an observation.
            return attestation.control(
                None, attestation.RUNTIME_CONFIG,
                "present in the runtime's record; not confirmed from inside "
                "the sandbox (no canary could be read back)",
            )

        # Compared in normalised form because the kernel records the mount
        # point normalised while HostConfig keeps the string as given.
        mounted_norm = {posixpath.normpath(m) for m in mounted}
        unmounted = [m for m in declared if posixpath.normpath(m) not in mounted_norm]
        if mounts.returncode != 0:
            detail = (
                "a canary planted behind every mask was unreadable from "
                "inside the sandbox; the mount table could not be read"
            )
        elif unmounted:
            # The canary is hidden but no tmpfs is mounted where we asked, so
            # something other than our mask is doing the hiding.
            return attestation.control(
                None, attestation.READBACK,
                "the canary was unreadable, but the sandbox's mount table "
                "shows no tmpfs at " + ", ".join(unmounted),
            )
        else:
            detail = (
                "a tmpfs is mounted at every declared path in the sandbox's "
                "own mount table, and a canary planted behind each one was "
                "unreadable from inside"
            )
        return attestation.control(True, attestation.READBACK, detail)

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
