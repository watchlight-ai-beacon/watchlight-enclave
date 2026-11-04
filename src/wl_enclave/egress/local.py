"""The local egress guard — a CONNECT allowlist in a sidecar container.

Topology, and why it is this one::

    +-- internal network (no route off the host) ----------+
    |                                                      |
    |   sandbox  --HTTP CONNECT-->  guard                  |
    |   (no other route)             |                     |
    +--------------------------------|---------------------+
                                     |  also attached to
                                     v  the default bridge
                                  upstream

The sandbox joins an **internal** Docker network, which has no route off the
host. The guard is attached to that network *and* to the default bridge, so it
is the only thing on the internal network that can reach anything. That makes
mediation structural rather than cooperative.

The distinction matters. Setting ``HTTP_PROXY`` on a sandbox that still has a
default route is a *request*, which code inside the sandbox is free to ignore
by opening a socket directly. Here the proxy variables are only a convenience
for libraries that read them; the enforcement is that there is nowhere else for
a packet to go. An agent that ignores the variables does not escape the guard,
it simply fails to connect — and either way the attempt is recorded or the
destination was unreachable.

What this does not cover, stated plainly because the records are evidence:

* **Only HTTP CONNECT attempts are recorded.** A raw TCP connection to an
  arbitrary port speaks no CONNECT, so the guard never sees it and cannot name
  it. It is still refused, because there is no route, but it surfaces as a
  connection failure inside the sandbox rather than a denial in the bundle.
  Blocked is not recorded, and a bundle must not be read as an account of every
  attempt.
* **The attestation is a topology check, not a packet-level guarantee.** It
  asks the runtime once, after the sandbox starts, whether the guard is its only
  attachment. It cannot see a route added later in the run, and it cannot see
  traffic that never reached the guard.

A packet filter inside the sandbox's own network namespace — accept proxy-bound
and established flows, log and reject the rest — is what turns the first limit
into per-attempt evidence and the second into a continuous guarantee. Where a
runtime already provides that and emits its own event stream, the right move is
to consume it rather than reimplement it, which is why the record schema lives
in :mod:`wl_enclave.egress` and the mechanism does not.
"""


from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from .. import attestation
from . import Allowlist, EgressEndpoint, GuardError

#: What a guard of this shape can and cannot put in a record. Carried into the
#: attestation so a reviewer reads a bundle's coverage off the bundle itself,
#: rather than having to know how the guard works.
RECORDS_COVER = ["http_connect"]
BLOCKED_NOT_RECORDED = ["raw_tcp", "udp", "icmp"]

#: What the guard prints once its listener is bound. Coupled to the guard's
#: own startup message on purpose: it is the only signal available that the
#: socket exists, given the runtime image ships no network tools. A test
#: asserts the two stay in step.
GUARD_READY_MARKER = "listening on"

#: How long to wait for the guard to start accepting before giving up.
GUARD_START_TIMEOUT = 15.0

#: Port the guard listens on inside the sandbox's network.
GUARD_PORT = 8080

#: Image tag built from ``crates/wl-enclave-egress``.
GUARD_IMAGE = "wl-enclave/egress:latest"

#: Where the guard writes its records inside its own container.
#:
#: Deliberately not ``/evidence``: that name belongs to the directory shared
#: with the sandbox, and anyone reading the guard's mount list would reasonably
#: conclude the guard wrote into it. The whole point of this path is that it is
#: somewhere the sandbox cannot reach.
RECORD_IN_GUARD = "/guard/egress.jsonl"

_CALL_TIMEOUT = 60


class LocalEgressGuard:
    """Runs ``wl-enclave-egress`` beside the sandbox on an internal network."""

    name = "local"

    def __init__(self, binary: str = "docker", crate_dir: Optional[Path] = None) -> None:
        self._bin = binary
        self._crate = crate_dir or Path(__file__).resolve().parents[3] / "crates" / "wl-enclave-egress"
        self._network: Optional[str] = None
        self._container: Optional[str] = None

    # -- plumbing ---------------------------------------------------------
    def _run(self, *args: str, timeout: int = _CALL_TIMEOUT, check: bool = True):
        try:
            proc = subprocess.run(
                [self._bin, *args], capture_output=True, text=True, timeout=timeout
            )
        except FileNotFoundError as exc:
            raise GuardError(f"{self._bin} is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise GuardError(f"{self._bin} {args[0]} timed out") from exc
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise GuardError(
                f"{self._bin} {args[0]} failed: "
                + (detail[-1] if detail else f"exit {proc.returncode}")
            )
        return proc

    @staticmethod
    def _reject_flaglike(label: str, value: str) -> None:
        """Refuse a value the runtime CLI would read as a flag.

        The same defence the Docker driver applies, for the same reason: an
        injected ``--network=host`` here would put the guard on the host's
        network and quietly dissolve the boundary it exists to enforce.
        """
        if not value or value.startswith("-"):
            raise GuardError(f"{label}: {value!r} would be read as a flag, so it is refused")

    # -- protocol ---------------------------------------------------------
    def preflight(self) -> list[str]:
        """Report what would stop the guard from running. Never raises."""
        if shutil.which(self._bin) is None:
            return [f"{self._bin} is not installed or not on PATH"]
        if not (self._crate / "Cargo.toml").is_file():
            return [f"the egress guard crate is missing from {self._crate}"]
        return []

    def start(self, run_id: str, allowlist: Allowlist, record_file: Path) -> EgressEndpoint:
        """Build the guard if needed, then bring up the network and the guard.

        The record file is created before the guard starts so the bind mount
        resolves to a file rather than a directory, and so an empty run still
        leaves an empty record rather than nothing at all.
        """
        if not allowlist:
            raise GuardError("the allowlist is empty; start() would admit nothing")

        self._ensure_image()

        network = f"wl-enclave-{run_id}-int"
        container = f"wl-enclave-{run_id}-egress"
        self._reject_flaglike("network name", network)
        self._reject_flaglike("guard name", container)

        record_file = Path(record_file)
        record_file.parent.mkdir(parents=True, exist_ok=True)
        record_file.touch(exist_ok=True)

        # An internal network has no route off the host. This is the boundary;
        # the proxy variables set on the sandbox are only a convenience.
        self._run("network", "create", "--internal", network)
        self._network = network

        try:
            self._run(
                "run", "--detach",
                "--name", container,
                "--network", network,
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "128",
                "--memory", str(256 * 1024**2),
                # The guard writes a line to stderr per failed connection, and
                # record writes are rate-limited while stderr is not. Without a
                # cap, a connect-then-reset loop inside the sandbox writes
                # unbounded host disk through the daemon's logging driver.
                "--log-opt", "max-size=16m",
                "--log-opt", "max-file=2",
                "--mount",
                f"type=bind,src={record_file.resolve()},dst={RECORD_IN_GUARD}",
                "--env", f"WL_EGRESS_LISTEN=0.0.0.0:{GUARD_PORT}",
                "--env", f"WL_EGRESS_ALLOW={','.join(allowlist.entries)}",
                "--env", f"WL_EGRESS_RECORD={RECORD_IN_GUARD}",
                GUARD_IMAGE,
            )
            self._container = container
            # Attach the guard to the default bridge as well: it is now the
            # only thing on the internal network with a way out.
            self._run("network", "connect", "bridge", container)
            # `run --detach` returns as soon as the container is created, so a
            # guard that exits immediately — a rejected allowlist, a port it
            # cannot bind — still looks like a successful start. The run would
            # then proceed with nothing listening: every connection refused by
            # absence rather than by policy, no records written, and a bundle
            # reading "attested, no attempts", which is the shape of a clean
            # run. Confirm it is actually up before handing out its address.
            self._await_listening(container)
        except GuardError:
            self.stop()
            raise

        return EgressEndpoint(host=container, port=GUARD_PORT)

    def network(self) -> Optional[str]:
        """The internal network the sandbox must join."""
        return self._network

    def stop(self) -> None:
        """Remove the guard and its network, leaving the records in place."""
        if self._container:
            self._run("rm", "--force", self._container, check=False)
            self._container = None
        if self._network:
            self._run("network", "rm", self._network, check=False)
            self._network = None

    def _await_listening(self, container: str) -> None:
        """Block until the guard is running and accepting, or raise.

        Polls rather than sleeping a fixed interval: a cold start is fast and a
        failure is faster still, and the error a dead guard leaves in its own
        logs is the only useful diagnosis available.
        """
        deadline = time.monotonic() + GUARD_START_TIMEOUT
        last = ""
        while time.monotonic() < deadline:
            state = self._run(
                "inspect", container, "--format", "{{.State.Status}}|{{.State.ExitCode}}",
                check=False, timeout=30,
            )
            status, _, exit_code = state.stdout.strip().partition("|")
            if status in {"exited", "dead"}:
                detail = (self.logs() or "").strip().splitlines()
                raise GuardError(
                    f"the guard exited immediately (status {status}, exit {exit_code})"
                    + (f": {detail[-1]}" if detail else "")
                )
            if status == "running":
                # The guard prints this only after its listener is bound, so
                # the line is proof the socket exists. Probing the port from
                # outside would need a tool the runtime image deliberately does
                # not ship, or a throwaway container on the internal network.
                last = self.logs()
                if GUARD_READY_MARKER in last:
                    return
            time.sleep(0.1)
        tail = (last or "").strip().splitlines()
        raise GuardError(
            f"the guard did not report a bound listener within {GUARD_START_TIMEOUT}s"
            + (f": {tail[-1]}" if tail else "")
        )

    def state(self) -> dict:
        """What the runtime says the guard container is doing right now.

        Read back rather than assumed, for the same reason the topology is: a
        container that exited still reports both its networks, so a guard that
        died one second into the run satisfies every attachment check in
        :meth:`attest` while having witnessed nothing since. ``OOMKilled`` is
        included because that is the likeliest way for it to die on its own —
        the memory ceiling is deliberately small.
        """
        if not self._container:
            return {}
        probe = self._run(
            "inspect", self._container, "--format",
            "{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}",
            check=False, timeout=30,
        )
        if probe.returncode != 0:
            return {"guard_state_unreadable": True}
        parts = probe.stdout.strip().split("|")
        if len(parts) != 3:
            return {"guard_state_unreadable": True}
        status, exit_code, oom = parts
        return {
            "guard_status": status,
            "guard_running": status == "running",
            "guard_exit_code": int(exit_code) if exit_code.lstrip("-").isdigit() else None,
            "guard_oom_killed": oom == "true",
        }

    def attest(self, sandbox_ref: Optional[str] = None) -> dict:
        """Read the network layout back out of Docker.

        Three facts are read rather than assumed, because each one is a way the
        boundary could be absent while every other part of the run looks
        normal:

        * the network is marked ``Internal``, so Docker gives it no route off
          the host;
        * the sandbox is attached to **that network and nothing else** — a
          second attachment is a direct path to the internet, and the one
          mistake most likely to be made by hand;
        * the guard is attached to the internal network *and* something else,
          which is what lets it forward at all.

        A missing or unreadable fact is reported as unknown and makes
        ``route_exclusive`` false. Unknown is not the same as safe.
        """
        facts: dict = {
            "guard": self.name,
            # How the boundary is held, and how strongly it was checked. A
            # reviewer comparing two bundles needs both: topology checked once
            # is a weaker claim than a packet filter checked continuously, and
            # collapsing them into a bare "attested" hides the difference.
            "enforcement": "network_topology",
            "verified_by": "runtime_readback",
            "records_cover": list(RECORDS_COVER),
            "blocked_not_recorded": list(BLOCKED_NOT_RECORDED),
            "network": self._network,
            "network_internal": None,
            "sandbox_networks": None,
            "guard_networks": None,
            "route_exclusive": False,
            "problems": [],
        }
        if not self._network:
            facts["problems"].append("no guard network: the sandbox had no mediated route")
            return facts

        internal = self._run(
            "network", "inspect", self._network, "--format", "{{.Internal}}",
            check=False, timeout=30,
        )
        if internal.returncode == 0:
            facts["network_internal"] = internal.stdout.strip() == "true"
        else:
            facts["problems"].append(f"could not inspect network {self._network}")

        if sandbox_ref:
            facts["sandbox_networks"] = self._networks_of(sandbox_ref, facts, "sandbox")
        else:
            facts["problems"].append("no sandbox reference: attachments not checked")

        if self._container:
            facts["guard_networks"] = self._networks_of(self._container, facts, "guard")
            facts.update(self.state())

        if facts.get("guard_running") is False:
            facts["problems"].append(
                f"the guard was not running when the topology was read "
                f"(exit {facts.get('guard_exit_code')}): anything the sandbox "
                f"attempted while it was down is absent from the records"
            )

        sandbox_nets = facts["sandbox_networks"]
        guard_nets = facts["guard_networks"] or []
        facts["route_exclusive"] = bool(
            facts["network_internal"] is True
            and sandbox_nets == [self._network]
            and self._network in guard_nets
            and len(guard_nets) > 1
        )

        # The same conclusion, broken out per control. route_exclusive stays
        # because it is the one-line answer, but it is a conjunction, and a
        # conjunction that comes out false does not say which term failed. Each
        # control also carries how its state was established, because a fact
        # read out of the runtime and a fact we merely asked for are the same
        # word in a bundle unless the record distinguishes them.
        extra_nets = [n for n in (sandbox_nets or []) if n != self._network]
        facts["controls"] = {
            attestation.NETWORK_UNROUTABLE: attestation.control(
                facts["network_internal"],
                attestation.READBACK,
                "" if facts["network_internal"] else
                "the network is not marked internal, so it has a gateway",
            ),
            attestation.SANDBOX_SINGLE_NETWORK: attestation.control(
                (sandbox_nets == [self._network]) if sandbox_nets else None,
                attestation.READBACK,
                ("also attached to " + ", ".join(extra_nets)) if extra_nets else "",
            ),
            attestation.GUARD_ATTACHED: attestation.control(
                (self._network in guard_nets) if guard_nets else None,
                attestation.READBACK,
            ),
            attestation.GUARD_HAS_EGRESS: attestation.control(
                (len(guard_nets) > 1) if guard_nets else None,
                attestation.READBACK,
                "" if len(guard_nets) > 1 else
                "the guard has no second network, so it could not forward",
            ),
            attestation.GUARD_LIVE: attestation.control(
                facts.get("guard_running"),
                attestation.READBACK,
                "" if facts.get("guard_running") else
                f"guard status {facts.get('guard_status')!r}, "
                f"exit {facts.get('guard_exit_code')}",
            ),
        }
        if sandbox_nets and sandbox_nets != [self._network]:
            extra = [n for n in sandbox_nets if n != self._network]
            facts["problems"].append(
                "the sandbox is also attached to " + ", ".join(extra)
                + ", so the guard was not its only route"
            )
        return facts

    def _networks_of(self, ref: str, facts: dict, label: str) -> Optional[list]:
        """The networks a container is attached to, sorted for a stable record."""
        proc = self._run(
            "inspect", ref,
            "--format", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
            check=False, timeout=30,
        )
        if proc.returncode != 0:
            facts["problems"].append(f"could not inspect the {label}")
            return None
        return sorted(proc.stdout.split())

    def logs(self) -> str:
        """The guard's own stderr, for diagnosing a guard that refused to start."""
        if not self._container:
            return ""
        proc = self._run("logs", self._container, check=False)
        return (proc.stdout or "") + (proc.stderr or "")

    # -- image ------------------------------------------------------------
    def _ensure_image(self) -> None:
        """Build the guard image if it is not present.

        Built on demand rather than pulled: the guard is in the data path, and
        building it from the source in this repository means what runs there is
        what was reviewed here.
        """
        present = self._run(
            "image", "inspect", GUARD_IMAGE, check=False, timeout=30
        ).returncode == 0
        if present:
            return
        self._run(
            "build",
            "--file", str(self._crate / "Dockerfile"),
            "--tag", GUARD_IMAGE,
            str(self._crate),
            timeout=900,
        )


def read_egress_records(record_file: Path) -> list[dict]:
    """Parse the guard's records, tolerating a truncated final line.

    A guard killed mid-write leaves one, and discarding the whole file over it
    would throw away the evidence the run was for.
    """
    path = Path(record_file)
    if not path.is_file():
        return []
    out: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
