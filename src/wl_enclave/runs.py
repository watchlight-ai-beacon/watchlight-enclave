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
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

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


#: Most decision records taken from one run's audit trail. The file is written
#: by the agent's own process, so without a cap a loop can make the chain
#: arbitrarily long and bury the records a reviewer came for.
MAX_DECISIONS = 10_000

#: Longest string kept from any field of an agent-authored record.
MAX_FIELD_CHARS = 512

#: Fields a decision must carry to be read as one.
_REQUIRED_DECISION_FIELDS = ("decision", "intent", "resource", "ts")

#: What the agent is allowed to say about itself, and nothing more. Any other
#: key is dropped rather than carried: an unknown field in an agent-authored
#: record is something a reader might believe.
_ALLOWED_DECISION_FIELDS = frozenset(
    {"agent", "decision", "decision_id", "event", "intent", "principal", "resource", "ts"}
)


def _scrub(value: Any) -> Any:
    """Make one agent-supplied value safe to put in front of a reviewer.

    Control characters are stripped because the chain is line-delimited JSON
    and a newline inside a value is how a single record becomes two. Length is
    capped because an unbounded field is an unbounded chain.
    """
    if isinstance(value, str):
        cleaned = "".join(ch for ch in value if ch.isprintable())
        if len(cleaned) > MAX_FIELD_CHARS:
            return cleaned[:MAX_FIELD_CHARS] + "…[truncated]"
        return cleaned
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _scrub(str(value))


def read_decisions(audit_file: Path) -> tuple[list[dict], dict]:
    """Parse Watchlight's audit trail, returning the records and an account.

    These are the only chain payloads the agent's own process authors: the
    audit file lives in the directory shared with the sandbox, by design,
    because the SDK inside it is what writes the decisions. Everything here
    follows from that. The records are not trusted as given — they are
    bounded, scrubbed, reduced to known fields, and stamped at this boundary
    with where they came from, overwriting anything the record claimed on that
    subject. A reviewer must never have to guess which records the subject of
    the investigation wrote about itself.

    Tolerates a truncated final line: a sandbox killed mid-write leaves one,
    and losing the whole trail over it would defeat the point.
    """
    account = {
        "malformed": 0,
        "truncated_fields": 0,
        "dropped_over_cap": 0,
        "rejected_not_a_regular_file": 0,
    }
    path = Path(audit_file)
    # Opened without following links. The sandbox owns the contents of this
    # directory, so it can replace the audit file with a symlink and have the
    # host read whatever it points at — a sibling bundle/chain.jsonl, for
    # instance, which the sandbox is never supposed to reach. The read is
    # bounded and field-filtered, so this was never a write or forgery
    # primitive, but it made the documented boundary ("guard/ and bundle/ are
    # kept out of the sandbox entirely") weaker for reads than it claims.
    #
    # O_NOFOLLOW fails on the final component being a link, which is the one
    # the sandbox controls; the parent components are ours.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return [], account
    except OSError:
        # ELOOP (a symlink) or anything else that is not a plain open.
        account["rejected_not_a_regular_file"] += 1
        return [], account

    out: list[dict] = []
    with os.fdopen(fd, encoding="utf-8") as fh:
        # Checked on the open descriptor, so there is no window between the
        # test and the read for the file to be swapped.
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            account["rejected_not_a_regular_file"] += 1
            return [], account
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                account["malformed"] += 1
                continue
            if not isinstance(raw, dict) or any(
                field not in raw for field in _REQUIRED_DECISION_FIELDS
            ):
                account["malformed"] += 1
                continue
            if len(out) >= MAX_DECISIONS:
                account["dropped_over_cap"] += 1
                continue
            record = {}
            for key, value in raw.items():
                if key not in _ALLOWED_DECISION_FIELDS:
                    continue
                scrubbed = _scrub(value)
                if scrubbed != value:
                    account["truncated_fields"] += 1
                record[key] = scrubbed
            # Stamped last so it overwrites, rather than merges with, whatever
            # the record said about its own provenance.
            record["asserted_by"] = "sandbox"
            out.append(record)
    return out, account
