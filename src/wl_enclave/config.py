"""``enclave.yaml`` — the whole configuration surface, deliberately small.

One file names the agent, the runtime to isolate it with, the policy bundle that
governs what authority it has, and under ``egress.allow`` the hosts it may
reach. Those are two separate questions and the file keeps them separate:
authority over a tool is not the same thing as reachability of a host, and
collapsing them would mean one could not be tightened without the other.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .egress import entry_problem

#: ``enclave.yaml`` schema version this build understands.
SCHEMA_VERSION = 1

#: Runtime drivers that may appear under ``runtime:``.
KNOWN_RUNTIMES = ("docker", "podman", "openshell")

_DURATION = re.compile(r"^(\d+)(s|m|h)$")
_SIZE = re.compile(r"^(\d+)(Mi|Gi)$", re.IGNORECASE)

#: An OCI image reference, constrained enough to be safe as an argv element.
#:
#: This is not a full implementation of the reference grammar. Its job is
#: narrower and security-critical: ``docker run`` treats every argument up to
#: the image as a flag, so an image value of ``--privileged`` (or
#: ``--network=host``, ``--cap-add=ALL``) would be parsed as one and would
#: defeat the isolation flags the driver sets. Anything that is not plainly a
#: reference is refused.
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$")


def _valid_image_ref(value: str) -> bool:
    """Whether ``value`` is safe to pass as the image argument.

    Rejects a leading ``-`` outright: that is the argument-injection case, and
    no legitimate reference begins with one.
    """
    return bool(value) and not value.startswith("-") and bool(_IMAGE_REF.match(value))


class ConfigError(Exception):
    """``enclave.yaml`` is missing, malformed, or refers to something absent.

    Carries every problem found, not just the first, so one run of
    ``wl-enclave doctor`` tells you everything to fix.
    """

    def __init__(self, path: Path, problems: list[str]) -> None:
        self.path = path
        self.problems = problems
        joined = "\n".join(f"  - {p}" for p in problems)
        super().__init__(f"{path}:\n{joined}")


@dataclass(frozen=True)
class Limits:
    """Resource ceilings applied to the sandbox."""

    memory: str = "2Gi"
    cpus: float = 2.0
    pids: int = 512
    timeout: str = "30m"

    @property
    def timeout_seconds(self) -> int:
        m = _DURATION.match(self.timeout)
        if not m:  # pragma: no cover - validated at load
            raise ValueError(self.timeout)
        n, unit = int(m.group(1)), m.group(2)
        return n * {"s": 1, "m": 60, "h": 3600}[unit]

    @property
    def memory_bytes(self) -> int:
        m = _SIZE.match(self.memory)
        if not m:  # pragma: no cover - validated at load
            raise ValueError(self.memory)
        n, unit = int(m.group(1)), m.group(2).lower()
        return n * {"mi": 1024**2, "gi": 1024**3}[unit]


@dataclass(frozen=True)
class Agent:
    """The harness to run inside the sandbox."""

    name: str
    command: list[str]
    image: Optional[str] = None
    build: Optional[str] = None


@dataclass(frozen=True)
class Config:
    """A loaded, validated ``enclave.yaml``."""

    path: Path
    agent: Agent
    runtime: str = "docker"
    policy: Path = Path("./policies")
    mcp_servers: list[str] = field(default_factory=list)
    egress_allow: list[str] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)

    @property
    def root(self) -> Path:
        """The directory ``enclave.yaml`` sits in. Relative paths resolve here."""
        return self.path.parent

    def governing_digests(self) -> dict:
        """Hashes of the files that decided what this run was allowed to do.

        The workspace is mounted writable, because an agent that cannot write
        code cannot do the job. That means ``enclave.yaml`` and the policy
        bundle are both reachable from inside the sandbox, so a run can change
        what the *next* run is permitted to do. Making them read-only is not
        available without taking away the workspace.

        What is available is making the change visible. Each bundle states the
        exact bytes that governed it, so two runs under silently different
        rules cannot read as two runs under the same rules — which is the part
        that would actually mislead a reviewer. A run that widened its
        successor's allowlist leaves the widening in its own evidence.

        This is not a signature and does not try to be. It proves two bundles
        were governed by different files; it proves nothing about which was
        the intended one.
        """
        files: dict[str, str] = {}
        for label, target in self._governing_files():
            try:
                files[label] = (
                    "sha256:"
                    + hashlib.sha256(target.read_bytes()).hexdigest()
                )
            except OSError as exc:
                files[label] = f"unreadable: {exc.strerror or exc}"
        # A digest over the per-file digests, so a reviewer comparing two runs
        # has one value to compare rather than a set. Keyed by label and
        # sorted, so it does not change when the filesystem's ordering does.
        combined = hashlib.sha256(
            "\n".join(f"{k}={v}" for k, v in sorted(files.items())).encode()
        ).hexdigest()
        return {"files": files, "combined": f"sha256:{combined}"}

    def _governing_files(self) -> list[tuple[str, Path]]:
        """``(label, path)`` for every file whose contents decide the rules."""
        out = [("enclave.yaml", self.path)]
        if self.policy.is_dir():
            for policy_file in sorted(self.policy.glob("*.policy.json")):
                out.append((f"policy/{policy_file.name}", policy_file))
        elif self.policy.is_file():
            out.append((f"policy/{self.policy.name}", self.policy))
        return out


def _require_str_list(raw: Any, where: str, problems: list[str]) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        problems.append(f"{where}: expected a list of strings")
        return []
    return list(raw)


def load(path: Path) -> Config:
    """Read and validate ``enclave.yaml``, reporting every problem at once.

    Raises :class:`ConfigError` listing each problem found. A valid file is
    returned as a frozen :class:`Config` with paths resolved against the file's
    own directory.
    """
    path = Path(path)
    if not path.is_file():
        raise ConfigError(path, ["no such file — run `wl-enclave init` to write one"])

    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(path, [f"not valid YAML: {exc}"]) from exc
    if not isinstance(raw, dict):
        raise ConfigError(path, ["the top level must be a mapping"])

    problems: list[str] = []

    version = raw.get("version")
    if version != SCHEMA_VERSION:
        problems.append(
            f"version: expected {SCHEMA_VERSION}, found {version!r}"
        )

    # --- agent -------------------------------------------------------------
    agent_raw = raw.get("agent")
    agent = None
    if not isinstance(agent_raw, dict):
        problems.append("agent: required, and must be a mapping")
    else:
        name = agent_raw.get("name")
        if not isinstance(name, str) or not name:
            problems.append("agent.name: required, a non-empty string")
            name = "agent"
        command = agent_raw.get("command")
        if not isinstance(command, list) or not command or not all(
            isinstance(x, str) for x in command
        ):
            problems.append(
                'agent.command: required, a non-empty list of strings '
                '(e.g. ["python", "agent.py"])'
            )
            command = []
        image, build = agent_raw.get("image"), agent_raw.get("build")
        if image is None and build is None:
            problems.append("agent: one of image: or build: is required")
        if image is not None and build is not None:
            problems.append("agent: give image: or build:, not both")
        if isinstance(image, str) and not _valid_image_ref(image):
            problems.append(
                f"agent.image: {image!r} is not a valid image reference "
                f"(it would be passed to the runtime as an argument)"
            )
        agent = Agent(
            name=name,
            command=list(command),
            image=image if isinstance(image, str) else None,
            build=build if isinstance(build, str) else None,
        )

    # --- runtime -----------------------------------------------------------
    runtime = raw.get("runtime", "docker")
    if runtime not in KNOWN_RUNTIMES:
        problems.append(
            f"runtime: {runtime!r} is not a driver this build has "
            f"(have: {', '.join(KNOWN_RUNTIMES)})"
        )

    # --- policy ------------------------------------------------------------
    policy = Path(raw.get("policy", "./policies"))
    resolved_policy = policy if policy.is_absolute() else path.parent / policy
    # Required to sit inside the project. The policy bundle is mounted into the
    # sandbox, so an unconstrained path here is a way to mount an arbitrary
    # host directory into a sandbox from a config file — and enclave.yaml is
    # itself inside the workspace a run can write to, which means a run could
    # choose what the next run mounts. Containment is checked after resolving
    # symlinks, because a symlink inside the project pointing out of it passes
    # a check made on the path as written.
    try:
        real_policy = resolved_policy.resolve()
        real_root = path.parent.resolve()
        contained = real_policy == real_root or real_root in real_policy.parents
    except OSError:
        contained = False
    if not contained:
        problems.append(
            f"policy: {policy} resolves outside the project directory; the "
            f"bundle is mounted into the sandbox, so it must be a path this "
            f"project owns"
        )
    elif not resolved_policy.exists():
        problems.append(f"policy: {policy} does not exist")
    elif resolved_policy.is_dir() and not any(resolved_policy.glob("*.policy.json")):
        problems.append(
            f"policy: {policy} holds no *.policy.json files "
            f"(the Watchlight policy-file format)"
        )

    # --- mcp ---------------------------------------------------------------
    mcp_raw = raw.get("mcp") or {}
    if not isinstance(mcp_raw, dict):
        problems.append("mcp: must be a mapping")
        mcp_raw = {}
    # Accepted and validated, but nothing in the run path consumes it yet, so
    # `init` does not write it. Kept here so a file that already names servers
    # keeps loading rather than failing on an unknown key.
    servers = _require_str_list(mcp_raw.get("servers"), "mcp.servers", problems)

    # --- egress ------------------------------------------------------------
    egress_raw = raw.get("egress") or {}
    if not isinstance(egress_raw, dict):
        problems.append("egress: must be a mapping")
        egress_raw = {}
    allow = _require_str_list(egress_raw.get("allow"), "egress.allow", problems)
    for entry in allow:
        # Validated by the guard's own rules, not a second copy of them: a
        # loader that accepts what the guard refuses lets a run start with a
        # guard that exits immediately.
        problem = entry_problem(entry)
        if problem:
            problems.append(f"egress.allow: {entry!r} {problem}")

    # --- limits ------------------------------------------------------------
    limits_raw = raw.get("limits") or {}
    if not isinstance(limits_raw, dict):
        problems.append("limits: must be a mapping")
        limits_raw = {}
    defaults = Limits()
    memory = str(limits_raw.get("memory", defaults.memory))
    if not _SIZE.match(memory):
        problems.append(f"limits.memory: {memory!r} must look like 512Mi or 2Gi")
        memory = defaults.memory
    timeout = str(limits_raw.get("timeout", defaults.timeout))
    if not _DURATION.match(timeout):
        problems.append(f"limits.timeout: {timeout!r} must look like 90s, 30m or 2h")
        timeout = defaults.timeout
    try:
        cpus = float(limits_raw.get("cpus", defaults.cpus))
        if cpus <= 0:
            raise ValueError
    except (TypeError, ValueError):
        problems.append("limits.cpus: must be a positive number")
        cpus = defaults.cpus
    try:
        pids = int(limits_raw.get("pids", defaults.pids))
        if pids <= 0:
            raise ValueError
    except (TypeError, ValueError):
        problems.append("limits.pids: must be a positive integer")
        pids = defaults.pids

    if problems:
        raise ConfigError(path, problems)

    assert agent is not None  # guarded above; no problems means it loaded
    return Config(
        path=path,
        agent=agent,
        runtime=runtime,
        policy=resolved_policy,
        mcp_servers=servers,
        egress_allow=allow,
        limits=Limits(memory=memory, cpus=cpus, pids=pids, timeout=timeout),
    )


#: What ``wl-enclave init`` writes. The comments are part of the deliverable:
#: this file is the entire configuration surface a developer sees.
TEMPLATE = """\
version: 1

agent:
  name: {name}
  command: ["python", "agent.py"]
  image: python:3.12-slim
  # build: ./Dockerfile        # ...or build an image instead of pulling one

runtime: docker                # docker | podman

policy: ./policies             # *.policy.json bundle: what authority the agent has

egress:
  allow: []                    # host:port the sandbox may reach; all else refused
  # - api.anthropic.com:443    # empty means no network at all

limits:
  memory: 2Gi
  cpus: 2
  pids: 512
  timeout: 30m
"""
