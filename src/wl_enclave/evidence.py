"""The evidence bundle — a hash-chained record of what a run was allowed to do.

A bundle answers one question for a reviewer who was not there and does not
trust us: *what did this agent actually do, and what stopped it?* It carries
three kinds of record, because no one layer can answer for the others:

``sandbox.attested``
    What the isolation runtime reports the sandbox is constrained to, read back
    from the runtime itself (see :meth:`~wl_enclave.drivers.RuntimeDriver.attest`).

``decision``
    Every authorization decision Watchlight made, with the principal, the
    declared intent, the resource and the verdict.

``egress.attempt``
    Every connection the sandbox tried to open, with the host, the port, the
    verdict and the rule that decided it. Watchlight knows the agent asked to
    use a tool; only something in the network path knows where it then tried
    to go.

``egress.records_suppressed``
    The guard's own statement that it dropped records it could not write. A
    bundle carrying one of these is incomplete by its own account, which
    :func:`verify` reports separately from whether the chain is intact.

``egress.attested``
    Whether the runtime confirms the guard was the sandbox's *only* route, read
    back from the runtime rather than assumed. This is what makes the
    ``egress.attempt`` records an account rather than a lower bound: if the
    sandbox had a second path to the network, anything it sent that way is
    absent from the bundle, and a reviewer has to know that.

Each record is chained to the one before it, so a record cannot be removed,
reordered or edited without breaking every hash that follows. ``wl-enclave
verify`` recomputes the whole chain with no account and no network.

**What this is not, yet.** The chain is unsigned, so it proves internal
consistency rather than origin: anyone who can rewrite the file can recompute
the chain over their edit. Signing is what makes a bundle evidence against its
own author, and it belongs to the governed control plane that holds the key.
Nothing here claims otherwise, and :func:`verify` says so in its report.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from . import attestation

__all__ = [
    "GENESIS",
    "CHAIN_FILE",
    "MANIFEST_FILE",
    "Record",
    "ChainWriter",
    "VerifyResult",
    "verify",
]

#: ``prev`` of the first record. A chain always starts from a known value, so a
#: truncated head is detectable rather than merely plausible.
GENESIS = "0" * 64

CHAIN_FILE = "chain.jsonl"
MANIFEST_FILE = "manifest.json"

#: Bundle format version, independent of the package version. A reviewer's
#: verifier needs to know what it is reading years from now.
FORMAT = "wl-enclave-evidence/1"


def _canonical(obj: Any) -> bytes:
    """Serialize deterministically: sorted keys, no incidental whitespace.

    Two processes must hash identical content identically, so nothing about
    Python's dict ordering or default spacing may leak into the digest.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Record:
    """One link in the chain."""

    seq: int
    ts: str
    type: str
    data: dict
    prev: str
    hash: str

    @staticmethod
    def digest(seq: int, ts: str, type: str, data: dict, prev: str) -> str:
        """Hash a record's content. ``hash`` itself is never an input."""
        return hashlib.sha256(
            _canonical({"seq": seq, "ts": ts, "type": type, "data": data, "prev": prev})
        ).hexdigest()

    def to_json(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "ts": self.ts,
                "type": self.type,
                "data": self.data,
                "prev": self.prev,
                "hash": self.hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class ChainWriter:
    """Appends records to a bundle, maintaining the chain as it goes.

    Opening an existing bundle resumes from its head, so a run that is being
    contained can seal what it already has rather than losing it.
    """

    def __init__(self, bundle_dir: Path) -> None:
        self.dir = Path(bundle_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / CHAIN_FILE
        self._seq = 0
        self._head = GENESIS
        if self.path.exists():
            for rec in _read_chain(self.path):
                self._seq = rec.seq + 1
                self._head = rec.hash

    @property
    def head(self) -> str:
        """Hash of the most recent record; ``GENESIS`` when empty."""
        return self._head

    @property
    def count(self) -> int:
        return self._seq

    def append(self, type: str, data: dict, ts: Optional[str] = None) -> Record:
        """Add one record and flush it to disk immediately.

        Flushing per record matters: a sandbox killed mid-run must leave behind
        everything that had already happened.
        """
        ts = ts or _now()
        seq = self._seq
        prev = self._head
        rec = Record(
            seq=seq,
            ts=ts,
            type=type,
            data=data,
            prev=prev,
            hash=Record.digest(seq, ts, type, data, prev),
        )
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(rec.to_json() + "\n")
            fh.flush()
        self._seq = seq + 1
        self._head = rec.hash
        return rec

    def extend(self, records: Iterable[tuple[str, dict]]) -> int:
        """Append many records, returning how many were written."""
        n = 0
        for type, data in records:
            self.append(type, data)
            n += 1
        return n

    def seal(self, manifest: dict) -> Path:
        """Write the manifest, pinning the chain's head and length.

        The head and count live in the manifest as well as in the chain so that
        a bundle with records removed from the end fails verification instead of
        simply looking shorter.
        """
        full = {
            "format": FORMAT,
            "sealed_at": _now(),
            "records": self._seq,
            "head": self._head,
            **manifest,
        }
        out = self.dir / MANIFEST_FILE
        out.write_text(json.dumps(full, indent=2, sort_keys=True) + "\n")
        return out


def _read_chain(path: Path) -> list[Record]:
    records: list[Record] = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: not valid JSON: {exc}") from exc
            missing = {"seq", "ts", "type", "data", "prev", "hash"} - set(raw)
            if missing:
                raise ValueError(
                    f"{path}:{lineno}: record is missing {', '.join(sorted(missing))}"
                )
            records.append(
                Record(
                    seq=raw["seq"],
                    ts=raw["ts"],
                    type=raw["type"],
                    data=raw["data"],
                    prev=raw["prev"],
                    hash=raw["hash"],
                )
            )
    return records


@dataclass
class VerifyResult:
    """What :func:`verify` found. ``ok`` is true only when nothing is wrong."""

    ok: bool
    records: int
    head: str
    problems: list[str]
    signed: bool = False
    #: ``True`` when the runtime confirmed the guard was the sandbox's only
    #: route, ``False`` when it did not, ``None`` when no guard ran. Not a
    #: chain problem: the chain can be perfectly intact and still describe a
    #: run whose egress was unmediated, which is exactly why it is separate.
    egress_attested: Optional[bool] = None
    #: What classes of attempt the guard could record at all. An attested run
    #: covering only ``http_connect`` still holds no record of a raw socket, so
    #: the two facts have to be read together.
    egress_covers: Optional[list] = None
    #: ``True`` when nothing in the chain says records were dropped. Separate
    #: from :attr:`ok` on purpose: an intact chain and a complete one are
    #: different claims, and collapsing them would make a run that hit a rate
    #: limit indistinguishable from one whose chain was tampered with.
    complete: bool = True
    #: How many records the guard reports dropping, when it says so.
    records_dropped: int = 0
    #: Why the bundle is incomplete, in a reviewer's terms. Distinct from
    #: :attr:`problems`, which is reserved for integrity failures.
    incomplete_reasons: list[str] = field(default_factory=list)
    #: Every named control from every attesting layer, merged. A reviewer
    #: asking why a bundle is weaker than expected is always asking about one
    #: of these, which is why they are not collapsed into a boolean.
    controls: dict = field(default_factory=dict)
    #: ``False`` when some control was established as not in force. A third
    #: claim, independent of the two above, because it fails differently: the
    #: chain can be intact and complete and still faithfully describe a run
    #: that was not properly contained. Collapsing it into either of the others
    #: would lose exactly the distinction this bundle exists to make.
    contained: bool = True

    @property
    def verdict(self) -> str:
        """What a gate should branch on: the worst of three separate claims.

        Ordered by what each one costs a reader. A broken chain comes first
        because nothing else in the bundle can be relied on once it fails. An
        uncontained run comes next: the record is trustworthy and describes a
        run whose isolation did not hold. Incomplete comes last — everything
        stated is true, and some of what happened is missing.
        """
        if not self.ok:
            return "failed"
        if not self.contained:
            return "uncontained"
        return "ok" if self.complete else "incomplete"

    @property
    def summary(self) -> str:
        if not self.ok:
            return f"FAILED — {len(self.problems)} problem(s)"
        note = "signed" if self.signed else "unsigned"
        if not self.contained:
            failed = ", ".join(attestation.failed_controls(self.controls))
            return (
                f"UNCONTAINED — {self.records} records, chain intact, {note}, "
                f"but these controls were not in force: {failed}"
            )
        if not self.complete:
            # The reasons differ — records dropped under a limit, or a guard
            # that stopped witnessing — so the summary counts them rather than
            # naming one. Describing a dead guard as "records it could not
            # write" was wrong in exactly the direction that matters: it
            # understated a gap while claiming to report it.
            count = len(self.incomplete_reasons)
            return (
                f"INCOMPLETE — {self.records} records, chain intact, {note}, "
                f"but incomplete by its own account ({count} reason"
                f"{'s' if count != 1 else ''})"
            )
        return f"OK — {self.records} records, chain intact, {note}"


def verify(bundle_dir: Path) -> VerifyResult:
    """Recompute a bundle's chain and check it against its manifest.

    Offline and self-contained: no account, no network, no Watchlight. Every
    problem found is reported, so one run tells a reviewer everything.
    """
    bundle_dir = Path(bundle_dir)
    problems: list[str] = []

    chain_path = bundle_dir / CHAIN_FILE
    if not chain_path.is_file():
        return VerifyResult(
            ok=False, records=0, head=GENESIS,
            problems=[f"no {CHAIN_FILE} in {bundle_dir}"],
        )

    try:
        records = _read_chain(chain_path)
    except ValueError as exc:
        return VerifyResult(ok=False, records=0, head=GENESIS, problems=[str(exc)])

    prev = GENESIS
    for i, rec in enumerate(records):
        if rec.seq != i:
            problems.append(f"record {i}: seq is {rec.seq}, expected {i} (reordered or removed)")
        if rec.prev != prev:
            problems.append(
                f"record {rec.seq}: prev {rec.prev[:12]}… does not match the "
                f"previous record's hash {prev[:12]}… (a record was changed or removed)"
            )
        expected = Record.digest(rec.seq, rec.ts, rec.type, rec.data, rec.prev)
        if rec.hash != expected:
            problems.append(
                f"record {rec.seq}: hash {rec.hash[:12]}… does not match its "
                f"content, which hashes to {expected[:12]}… (the record was edited)"
            )
        prev = rec.hash

    head = records[-1].hash if records else GENESIS

    manifest_path = bundle_dir / MANIFEST_FILE
    if not manifest_path.is_file():
        problems.append(f"no {MANIFEST_FILE} — the bundle was never sealed")
    else:
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as exc:
            manifest = {}
            problems.append(f"{MANIFEST_FILE}: not valid JSON: {exc}")
        if manifest:
            if manifest.get("format") != FORMAT:
                problems.append(
                    f"{MANIFEST_FILE}: format is {manifest.get('format')!r}, "
                    f"this verifier reads {FORMAT!r}"
                )
            if manifest.get("head") != head:
                problems.append(
                    f"{MANIFEST_FILE}: head {str(manifest.get('head'))[:12]}… does not "
                    f"match the chain's head {head[:12]}… (records added or removed "
                    f"at the end)"
                )
            if manifest.get("records") != len(records):
                problems.append(
                    f"{MANIFEST_FILE}: says {manifest.get('records')} records, "
                    f"the chain holds {len(records)}"
                )

    # Read from the chain rather than recomputed: this reports what the run
    # claimed about its own topology, which the chain's integrity is what makes
    # trustworthy. A bundle with no such record ran without a guard.
    # The FIRST attestation wins, and a second is a problem rather than an
    # update. Taking the last would let anything able to append a record
    # overwrite the finding with a more flattering one; a run writes exactly
    # one, so more than one means something else wrote it.
    egress_attested: Optional[bool] = None
    egress_covers: Optional[list] = None
    attestations = [r for r in records if r.type == "egress.attested"]
    if attestations:
        first = attestations[0]
        egress_attested = bool(first.data.get("route_exclusive"))
        egress_covers = first.data.get("records_cover")
    if len(attestations) > 1:
        problems.append(
            f"{CHAIN_FILE}: {len(attestations)} egress attestations, but a run "
            f"writes one — the extra records did not come from this run's guard "
            f"(reporting the first, at seq {attestations[0].seq})"
        )

    # A guard that could not write a record says so in the record file, and
    # that note is chained like any other. It is the one record whose whole
    # purpose is to deny the file's completeness, so it must reach the verdict:
    # left unread, a rate-limited run verifies as "OK — chain intact" and a
    # reviewer has no way to learn the file is an understatement.
    suppressions = [r for r in records if r.type == "egress.records_suppressed"]
    records_dropped = 0
    for note in suppressions:
        value = note.data.get("records_dropped")
        if isinstance(value, int) and value > records_dropped:
            records_dropped = value

    # A guard that stopped before the run did is the other way the egress
    # records become a lower bound: not records dropped under a limit, but
    # records never taken, because nothing was watching. Both make the file an
    # understatement, so both land on the same verdict.
    stopped = [r for r in records if r.type == "egress.guard_stopped"]

    # Kept out of `problems` deliberately. A problem is an integrity failure —
    # a record edited, removed or reordered — and an incomplete bundle is a
    # different thing: everything in it is true, and some of what happened is
    # missing. Collapsing the two would make a rate-limited run read exactly
    # like a tampered one, which is how a reviewer learns to ignore both.
    # Controls from every attesting layer, read out of the records. A control
    # established as not in force is an integrity-relevant finding — the layer
    # did not hold — while one that could not be determined is the same kind of
    # fact as a dropped record: everything stated is true and something is
    # unknown. The two therefore land on different halves of the verdict.
    controls: dict[str, dict] = {}
    for record in records:
        if record.type in {"sandbox.attested", "egress.attested"}:
            found = record.data.get("controls")
            if not isinstance(found, dict):
                found = (record.data.get("constraints") or {}).get("controls")
            if isinstance(found, dict):
                controls = attestation.merge(controls, found)
        elif record.type == "egress.guard_stopped":
            # The guard's fate is known only at the end, after the topology
            # was attested. Folded in as a control so it reaches the same
            # summary rather than living only in its own record.
            controls = attestation.merge(
                controls,
                {
                    attestation.GUARD_LIVE: attestation.control(
                        False,
                        attestation.READBACK,
                        f"stopped before the run ended, exit "
                        f"{record.data.get('guard_exit_code')}",
                    )
                },
            )

    incomplete_reasons: list[str] = []
    if suppressions:
        dropped = f"{records_dropped} " if records_dropped else ""
        incomplete_reasons.append(
            f"the guard reports {dropped}record(s) it could not write, so the "
            f"egress records are a lower bound"
        )
    for name in attestation.unverified_controls(controls):
        detail = (controls[name].get("detail") or "").strip()
        incomplete_reasons.append(
            f"control {name!r} could not be confirmed"
            + (f": {detail}" if detail else "")
        )
    if stopped:
        incomplete_reasons.append(
            f"the egress guard stopped before the run ended "
            f"(exit {stopped[0].data.get('guard_exit_code')}); attempts made "
            f"after that are absent rather than denied"
        )

    return VerifyResult(
        ok=not problems,
        records=len(records),
        head=head,
        problems=problems,
        signed=False,
        egress_attested=egress_attested,
        egress_covers=egress_covers,
        complete=not incomplete_reasons,
        records_dropped=records_dropped,
        incomplete_reasons=incomplete_reasons,
        controls=controls,
        contained=not attestation.failed_controls(controls),
    )
