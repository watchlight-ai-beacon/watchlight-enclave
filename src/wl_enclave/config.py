"""``enclave.yaml`` — the whole configuration surface, deliberately small.

One file names the agent, the runtime to isolate it with, the policy bundle that
governs it, and what it may reach. The ``policy`` bundle feeds **both** layers:
Cedar governs authority, and the same bundle compiles to the sandbox's egress
rules, so the two cannot drift apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

#: ``enclave.yaml`` schema version this build understands.
SCHEMA_VERSION = 1

#: Runtime drivers that may appear under ``runtime:``.
KNOWN_RUNTIMES = ("docker", "podman", "openshell")

_DURATION = re.compile(r"^(\d+)(s|m|h)$")
_SIZE = re.compile(r"^(\d+)(Mi|Gi)$", re.IGNORECASE)
_HOSTPORT = re.compile(r"^(?P<host>[A-Za-z0-9._*-]+):(?P<port>\d{1,5})$")


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
    requirements: Optional[str] = None


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
        agent = Agent(
            name=name,
            command=list(command),
            image=image if isinstance(image, str) else None,
            build=build if isinstance(build, str) else None,
            requirements=agent_raw.get("requirements"),
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
    if not resolved_policy.exists():
        problems.append(f"policy: {policy} does not exist")
    elif resolved_policy.is_dir() and not any(resolved_policy.glob("*.cedar")):
        problems.append(f"policy: {policy} holds no .cedar files")

    # --- mcp ---------------------------------------------------------------
    mcp_raw = raw.get("mcp") or {}
    if not isinstance(mcp_raw, dict):
        problems.append("mcp: must be a mapping")
        mcp_raw = {}
    servers = _require_str_list(mcp_raw.get("servers"), "mcp.servers", problems)

    # --- egress ------------------------------------------------------------
    egress_raw = raw.get("egress") or {}
    if not isinstance(egress_raw, dict):
        problems.append("egress: must be a mapping")
        egress_raw = {}
    allow = _require_str_list(egress_raw.get("allow"), "egress.allow", problems)
    for entry in allow:
        if not _HOSTPORT.match(entry):
            problems.append(
                f"egress.allow: {entry!r} must be host:port (e.g. api.anthropic.com:443)"
            )

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
  # requirements: requirements.txt

runtime: docker                # docker | podman | openshell

policy: ./policies             # Cedar bundle; compiled to BOTH layers

mcp:
  servers: []                  # MCP servers to intercept, by name

egress:
  allow: []                    # host:port the sandbox may reach; all else refused
  # - api.anthropic.com:443

limits:
  memory: 2Gi
  cpus: 2
  pids: 512
  timeout: 30m
"""
