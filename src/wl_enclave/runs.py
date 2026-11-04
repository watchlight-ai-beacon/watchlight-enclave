"""Run directories — where a single governed run keeps its working state.

One directory per run, named so that listing them is chronological::

    runs/20261104-203145-7f3a1c/
        evidence/audit.jsonl   mounted into the sandbox; Watchlight writes here
        guard/egress.jsonl     mounted into the GUARD only; every attempt lands here
        bundle/chain.jsonl     the hash-chained evidence
        bundle/manifest.json   written when the run is sealed
        logs.txt               whatever the sandbox printed

``evidence/`` is the one path the sandbox can write to that outlives it, which
is what lets a contained run still produce a bundle. It is therefore also the
one directory whose contents are attacker-controlled, so ``guard/`` and
``bundle/`` are kept out of the sandbox entirely.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

#: Directory under the project root that holds every run.
RUNS_DIR = "runs"


def new_run_id() -> str:
    """A sortable, collision-resistant run id: ``20261104-203145-7f3a1c``."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(3)}"


@dataclass(frozen=True)
class Run:
    """The on-disk layout of one run."""

    id: str
    dir: Path

    @property
    def evidence_dir(self) -> Path:
        """Written by the sandbox. The only such path that survives it."""
        return self.dir / "evidence"

    @property
    def audit_file(self) -> Path:
        """Watchlight's decision trail, as written from inside the sandbox."""
        return self.evidence_dir / "audit.jsonl"

    @property
    def guard_dir(self) -> Path:
        """Written by the egress guard, and **never mounted into the sandbox**.

        Deliberately not under :attr:`evidence_dir`. That directory has to be
        writable by the sandbox, because the Watchlight SDK writes its decision
        trail from inside it. The guard's records must not be: the guard exists
        to be a witness the agent cannot influence, and a witness whose notes
        the subject can edit is not one. Sharing the directory would let the
        agent truncate the file, or unlink and recreate it so the guard went on
        writing to an orphaned inode while the host read the agent's version.
        """
        return self.dir / "guard"

    @property
    def egress_file(self) -> Path:
        """The guard's record of every attempt, in a directory the sandbox
        cannot reach."""
        return self.guard_dir / "egress.jsonl"

    @property
    def bundle_dir(self) -> Path:
        return self.dir / "bundle"

    @property
    def log_file(self) -> Path:
        return self.dir / "logs.txt"

    @property
    def meta_file(self) -> Path:
        return self.dir / "run.json"

    def create(self) -> "Run":
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.guard_dir.mkdir(parents=True, exist_ok=True)
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        return self

    def write_meta(self, **fields) -> None:
        self.meta_file.write_text(json.dumps(fields, indent=2, sort_keys=True) + "\n")

    def read_meta(self) -> dict:
        if not self.meta_file.is_file():
            return {}
        try:
            return json.loads(self.meta_file.read_text())
        except json.JSONDecodeError:
            return {}


def run_dir(root: Path, run_id: str) -> Run:
    return Run(id=run_id, dir=Path(root) / RUNS_DIR / run_id)


def create_run(root: Path) -> Run:
    """Allocate and create a fresh run directory."""
    return run_dir(root, new_run_id()).create()


def iter_runs(root: Path) -> Iterator[Run]:
    """Every run on disk, newest first."""
    base = Path(root) / RUNS_DIR
    if not base.is_dir():
        return
    for path in sorted(base.iterdir(), reverse=True):
        if path.is_dir():
            yield Run(id=path.name, dir=path)


def find_run(root: Path, run_id: str) -> Optional[Run]:
    """Resolve a run by id, or by a unique prefix of one."""
    candidates = [r for r in iter_runs(root) if r.id == run_id]
    if candidates:
        return candidates[0]
    prefixed = [r for r in iter_runs(root) if r.id.startswith(run_id)]
    return prefixed[0] if len(prefixed) == 1 else None


def read_decisions(audit_file: Path) -> list[dict]:
    """Parse Watchlight's audit trail into decision records.

    Tolerates a truncated final line: a sandbox killed mid-write leaves one,
    and losing the whole trail over it would defeat the point.
    """
    if not Path(audit_file).is_file():
        return []
    out: list[dict] = []
    with Path(audit_file).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
