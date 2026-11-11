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

from . import attestation, signing

__all__ = [
    "GENESIS",
    "BrokenChain",
    "CHAIN_FILE",
    "MANIFEST_FILE",
    "SIGNATURE_FIELDS",
    "Record",
    "ChainWriter",
    "VerifyResult",
    "manifest_body",
    "verify",
]

#: ``prev`` of the first record. A chain always starts from a known value, so a
#: truncated head is detectable rather than merely plausible.
GENESIS = "0" * 64

CHAIN_FILE = "chain.jsonl"
MANIFEST_FILE = "manifest.json"

#: Bundle format version, independent of the package version. A reviewer's
#: verifier needs to know what it is reading years from now.
#:
#: Signatures did not move this. The rule is that the version changes when an
#: older verifier would *misread* a newer bundle, and one that predates signing
#: ignores the new fields and reports a signed bundle as unsigned — weaker than
#: the truth, which is the only direction a stale verifier is allowed to err.
FORMAT = "wl-enclave-evidence/1"

#: Manifest keys a signature does not cover, because they carry the signatures
#: themselves. Excluding ``cosignatures`` is what makes a witness addable later
#: without invalidating the operator's signature: both sign the same bytes, and
#: neither signs the other's entry.
SIGNATURE_FIELDS = ("signature", "cosignatures")


def _canonical(obj: Any) -> bytes:
    """Serialize deterministically: sorted keys, no incidental whitespace.

    Two processes must hash identical content identically, so nothing about
    Python's dict ordering or default spacing may leak into the digest.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_body(manifest: dict) -> bytes:
    """The exact bytes a manifest signature covers.

    One function, used by the writer and the verifier, because a signature is
    only as good as both sides agreeing byte-for-byte on what was signed. A
    second implementation that serialized even slightly differently would
    produce a verification failure indistinguishable from tampering.
    """
    return _canonical(
        {k: v for k, v in manifest.items() if k not in SIGNATURE_FIELDS}
    )


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


class BrokenChain(Exception):
    """An existing chain failed verification, so it must not be extended."""


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
            # Verified before it is extended, not merely read. Resuming from
            # the head of a chain nobody checked is how tampering becomes
            # self-consistent: append onto an edited record and seal a fresh
            # manifest over the result, and every hash from the edit onward is
            # recomputed to agree with it. The one operation that would have
            # caught the edit is the one that overwrites the evidence of it.
            try:
                existing = _read_chain(self.path)
            except ValueError as exc:
                raise BrokenChain(f"{self.path}: {exc}") from exc
            prev = GENESIS
            for i, rec in enumerate(existing):
                if rec.seq != i or rec.prev != prev:
                    raise BrokenChain(
                        f"{self.path}: record {i} does not follow the one "
                        f"before it; refusing to extend a chain that does not "
                        f"verify"
                    )
                if rec.hash != Record.digest(
                    rec.seq, rec.ts, rec.type, rec.data, rec.prev
                ):
                    raise BrokenChain(
                        f"{self.path}: record {rec.seq} does not match its own "
                        f"content; refusing to extend a chain that does not "
                        f"verify"
                    )
                prev = rec.hash
            if existing:
                self._seq = existing[-1].seq + 1
                self._head = existing[-1].hash

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

    def seal(self, manifest: dict, signer: Optional["signing.Signer"] = None) -> Path:
        """Write the manifest, pinning the chain's head and length.

        The head and count live in the manifest as well as in the chain so that
        a bundle with records removed from the end fails verification instead of
        simply looking shorter.

        With a ``signer``, the manifest carries a signature over exactly the
        bytes :func:`manifest_body` produces. ``cosignatures`` is written empty
        either way: a reader should be able to tell a bundle that has no
        witness from one whose witness list this build did not know to write.
        """
        full = {
            "format": FORMAT,
            "sealed_at": _now(),
            "records": self._seq,
            "head": self._head,
            **manifest,
            "cosignatures": [],
        }
        if signer is not None:
            full["signature"] = signer.sign(manifest_body(full))
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
    #: The key that signed the manifest, when one did. Carried separately from
    #: :attr:`signed` because a verifying signature and a *known* signer are
    #: different claims: the public key travels in the bundle, so a signature
    #: alone says the manifest is unchanged, not who sealed it.
    signer_key_id: str = ""
    #: ``True`` only when the caller named an expected key and it matched. This
    #: is the rung that says something about *who*, and nothing sets it unless
    #: a reviewer asked the question.
    signer_pinned: bool = False
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
    @property
    def chain_intact(self) -> bool:
        """What :attr:`ok` actually means, under a name that says so.

        ``ok`` predates the three-claim split and was documented as "nothing is
        wrong". It is now exactly "the chain verifies", and two call sites
        believed the docstring: ``wl-enclave ps`` printed ``ok`` for every
        uncontained bundle, and ``evidence export`` let one through without
        ``--force``. Call sites should branch on :attr:`verdict`.
        """
        return self.ok

    #: Digest of the files that decided what this run was allowed to do. Two
    #: bundles with different values here were governed by different rules,
    #: whatever their summaries say — which matters because the workspace is
    #: writable and a run can edit its successor's rules.
    governed_by: str = ""
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
        # Three words, not two. "signed" on its own is what a reader wants to
        # hear and more than the bundle establishes: the public key rides along
        # in the manifest, so a verifying signature means the manifest is
        # unchanged, not that a known party sealed it. Only a pinned key says
        # who, and the summary is the line most likely to be quoted without
        # the detail beneath it.
        note = (
            "signed by the expected key"
            if self.signer_pinned
            else "self-signed" if self.signed else "unsigned"
        )
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


#: How a run finishes under its own steam: ``run.close`` completed and
#: ``run.error`` failed before it was under way. Exactly one, and it is the last
#: record, because anything after it would describe a run that had already ended.
#: The rule files are read at both ends of a run and recorded separately.
#: ``config.reattested`` is its own type so that a verifier predating it skips
#: a record it does not recognise, rather than reading the closing digest as
#: the answer to what governed the run.
_GOVERNING_RECORDS = frozenset({"config.attested", "config.reattested"})


def _rules_that_moved(opened: dict, closed: dict) -> list[str]:
    """Name the governing files that differ between the two readings.

    A combined digest is enough to know something moved, and useless for doing
    anything about it. The per-file comparison tells a reviewer whether a
    policy was rewritten or merely added, which is the difference between a run
    that widened its own authority and one that was handed another rule.
    """
    before = opened.get("files") or {}
    after = closed.get("files") or {}
    moved = []
    for name in sorted(set(before) | set(after)):
        was, now = before.get(name), after.get(name)
        if was == now:
            continue
        if was is None:
            moved.append(f"{name} appeared during the run")
        elif now is None:
            moved.append(f"{name} was removed during the run")
        else:
            moved.append(f"{name} was rewritten")
    return moved


_ENDING_RECORDS = frozenset({"run.close", "run.error"})

#: ``run.contained`` says the run was stopped — by its timeout, or by an
#: operator reaching for ``kill``. It is not an ending, because a stopped run
#: still closes: the timeout path contains the sandbox and then seals with
#: ``run.close`` and its tallies. It *may* be the last record, when whatever
#: would have closed the chain never got to, and that is why a chain ending here
#: is not treated as missing its end.
#:
#: Both sets together are what "says how the run ended" means. A chain with
#: nothing from either is missing its end, which is indistinguishable from
#: having been truncated.
_TERMINAL_RECORDS = _ENDING_RECORDS | frozenset({"run.contained"})

#: ``run.close`` field -> the record type it counts. Only fields that count
#: chain records one-for-one appear here; a derived total (``egress_allowed``,
#: say, which splits one type by verdict) is reconciled separately or not at
#: all, because a mismatch there would not mean what this check means.
_CLOSE_TALLIES = {
    "decisions": "decision",
    "egress_attempts": "egress.attempt",
    "egress_malformed": "egress.malformed",
    "egress_tunnels": "egress.tunnel",
    "egress_tunnel_progress_notes": "egress.tunnel_progress",
    "egress_saturated_notes": "egress.saturated",
    "egress_records_suppressed": "egress.records_suppressed",
}


def _expects_egress(records: list[Record]) -> bool:
    """Whether a guard was started, and therefore owes an attestation."""
    return any(r.type == "egress.guard_started" for r in records)


def _reconcile_close(records: list[Record]) -> list[str]:
    """Where ``run.close``'s own tallies disagree with the chain holding them.

    The bundle counts what it ingested and then stores those counts next to
    the records themselves, which is the one internal cross-check the format
    has. Ignoring it wasted it: records lost between ingest and seal — a
    truncated guard file, a second ingest path, an edit before sealing — leave
    a chain that is perfectly consistent and quietly short.

    A disagreement is an integrity problem rather than an incompleteness one.
    The bundle is not reporting a gap it knows about; it is making two
    statements that cannot both be true.
    """
    closes = [r for r in records if r.type == "run.close"]
    if not closes:
        return []
    data = closes[0].data
    actual: dict[str, int] = {}
    for record in records:
        actual[record.type] = actual.get(record.type, 0) + 1

    problems = []
    for field, kind in sorted(_CLOSE_TALLIES.items()):
        claimed = data.get(field)
        if not isinstance(claimed, int):
            continue
        held = actual.get(kind, 0)
        if claimed != held:
            problems.append(
                f"{CHAIN_FILE}: run.close says {field}={claimed}, but the "
                f"chain holds {held} {kind} record(s)"
            )
    return problems


def records(bundle_dir: Path) -> list[Record]:
    """A bundle's records, parsed by the same reader :func:`verify` uses.

    Exposed so that a caller wanting to read a bundle's contents cannot end up
    with a second, more forgiving parser. A line this rejects must not be a
    line some other feature silently accepts — that difference is how a
    reporting command comes to describe a bundle the verifier would refuse.
    """
    return _read_chain(Path(bundle_dir) / CHAIN_FILE)


def _check_signature(
    manifest: dict, expect_key: Optional[str]
) -> tuple[bool, str, bool, list[str]]:
    """Check a manifest's signature, and whether it came from the pinned key.

    Returns ``(signed, key_id, pinned, problems)``. A signature that verifies
    but belongs to a key other than the expected one still returns
    ``signed=True`` — it did verify — alongside a problem, because those are
    two separate facts and collapsing them would report a validly signed
    bundle as unsigned.
    """
    problems: list[str] = []
    entry = manifest.get("signature")

    # Cosignatures are checked whether or not an operator signature is present,
    # and checked even though nothing writes them yet. A verifier that skipped
    # the list would accept a forged witness entry the day one appears, and the
    # whole point of reserving the slot now is that adding a real witness later
    # needs no change here.
    cosignatures = manifest.get("cosignatures")
    if isinstance(cosignatures, list):
        for i, cosignature in enumerate(cosignatures):
            cosigned, detail = signing.check(manifest_body(manifest), cosignature)
            if not cosigned:
                problems.append(
                    f"{MANIFEST_FILE}: cosignature {i} does not verify — {detail}"
                )
    elif cosignatures is not None:
        problems.append(
            f"{MANIFEST_FILE}: cosignatures is "
            f"{type(cosignatures).__name__}, expected a list"
        )

    if entry is None:
        if expect_key:
            problems.append(
                f"{MANIFEST_FILE}: not signed, but a signature from "
                f"{expect_key} was required"
            )
        return False, "", False, problems

    ok, detail = signing.check(manifest_body(manifest), entry)
    if not ok:
        problems.append(f"{MANIFEST_FILE}: signature does not verify — {detail}")
        return False, "", False, problems

    key_id = detail
    pinned = False
    if expect_key:
        if key_id == expect_key:
            pinned = True
        else:
            problems.append(
                f"{MANIFEST_FILE}: signed by {key_id}, not by the required "
                f"{expect_key}"
            )
    return True, key_id, pinned, problems


def verify(
    bundle_dir: Path,
    require_signature: bool = False,
    expect_key: Optional[str] = None,
) -> VerifyResult:
    """Recompute a bundle's chain and check it against its manifest.

    Offline and self-contained: no account, no network, no Watchlight. Every
    problem found is reported, so one run tells a reviewer everything.

    ``require_signature`` and ``expect_key`` are both off by default, so this
    reads an unsigned bundle exactly as it did before signing existed. That
    default is deliberate: tightening it would break every gate standing on a
    bundle sealed by an older build, which is the failure mode the separately
    versioned verifier contract exists to avoid.

    The two land on different verdicts, because they fail differently. A
    missing signature where one was required is a gap — everything in the
    bundle is still true — so it reads ``incomplete``. A signature that does
    not verify, or one from a key other than the pinned one, is a positive
    contradiction, so it reads ``failed``.
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

    signed = False
    signer_key_id = ""
    signer_pinned = False

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
            signed, signer_key_id, signer_pinned, sig_problems = _check_signature(
                manifest, expect_key
            )
            problems.extend(sig_problems)

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
    incomplete_reasons: list[str] = []
    governed_by = ""
    governing: dict[str, dict] = {}
    for record in records:
        if record.type in {"sandbox.attested", "egress.attested"}:
            found = record.data.get("controls")
            if not isinstance(found, dict):
                found = (record.data.get("constraints") or {}).get("controls")
            if isinstance(found, dict):
                controls = attestation.merge(controls, found)
        elif record.type in _GOVERNING_RECORDS:
            digests = record.data.get("digests")
            if isinstance(digests, dict):
                governing[record.type] = digests
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


    # What governed the run, and whether it held still. The policy directory
    # sits inside the writable workspace, so an agent can rewrite the rules it
    # is being judged by; comparing the two readings is what makes that visible
    # rather than leaving the opening digest to speak for the whole run.
    opened = governing.get("config.attested")
    closed = governing.get("config.reattested")
    if isinstance(opened, dict):
        governed_by = opened.get("combined") or ""
    elif isinstance(closed, dict):
        governed_by = closed.get("combined") or ""

    unreadable = sorted(
        {
            name
            for reading in governing.values()
            for name, value in (reading.get("files") or {}).items()
            if isinstance(value, str) and not value.startswith("sha256:")
        }
    )
    if unreadable:
        # A rule file that could not be read is a rule we cannot state.
        # Incomplete rather than failed: the chain is sound and one of its
        # claims is missing.
        incomplete_reasons.append(
            "the bundle cannot state what governed the run; "
            "unreadable: " + ", ".join(unreadable)
        )

    if isinstance(opened, dict) and isinstance(closed, dict):
        moved = _rules_that_moved(opened, closed)
        if moved:
            # A problem rather than an incompleteness. Nothing here is missing:
            # the bundle makes two statements about what the run was allowed to
            # do, and they cannot both be true, which is the same reasoning that
            # makes a run.close tally that disagrees with the chain a problem.
            problems.append(
                f"{CHAIN_FILE}: the rules changed while the run was under way "
                f"({', '.join(moved)}); the bundle states what governed the "
                f"start and what governed the end and they differ, so it cannot "
                f"say which rules any decision in it was taken under"
            )

    write_errors = 0
    for note in suppressions:
        value = note.data.get("write_errors")
        if isinstance(value, int) and value > write_errors:
            write_errors = value
    if suppressions:
        dropped = f"{records_dropped} " if records_dropped else ""
        incomplete_reasons.append(
            f"the guard reports {dropped}record(s) it could not write, so the "
            f"egress records are a lower bound"
        )
    if write_errors:
        # Distinct from a budget drop, and worse: the budget is a limit we
        # chose, while this is the evidence file refusing writes. Named
        # separately so a reviewer is not told the guard was merely busy.
        incomplete_reasons.append(
            f"{write_errors} record(s) could not be written to the guard's "
            f"evidence file at all; connections they described were refused, "
            f"but the file is short by that many"
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

    # -- what the bundle does NOT say ------------------------------------
    #
    # Everything above reads a record that volunteered something. On its own
    # that makes absence indistinguishable from compliance, which is the exact
    # inversion of what this format is for: the shortest, emptiest bundle would
    # be the cleanest. So the checks below ask whether the records that must
    # exist do exist, rather than waiting to be told.

    # A run ends exactly once, and says so. Without this a bundle holding only
    # run.open verifies as OK, and a run that died before it had a sandbox
    # produces a shorter, cleaner bundle than one that completed.
    #
    # Counting every terminal record as an ending was wrong in both directions.
    # A timed-out run records run.contained and then seals with run.close, which
    # read as two endings and FAILED a bundle that was in fact sound. And a run
    # killed by an operator, whose chain ends at run.contained because nothing
    # closed it, read as a single clean ending and verified OK — the same
    # verdict as a run that finished. The second is the one that mattered: it
    # let a bundle understate what happened.
    endings = [r for r in records if r.type in _ENDING_RECORDS]
    contained = [r for r in records if r.type == "run.contained"]
    if not endings and not contained:
        problems.append(
            f"{CHAIN_FILE}: no {' / '.join(sorted(_TERMINAL_RECORDS))} record; "
            f"the chain does not say how the run ended, so records may be "
            f"missing from the end"
        )
    elif len(endings) > 1:
        problems.append(
            f"{CHAIN_FILE}: {len(endings)} records end the run, but a run ends "
            f"once: " + ", ".join(f"{r.type}@{r.seq}" for r in endings)
        )
    elif endings and endings[0].seq != records[-1].seq:
        # An ending that is not last means records describe a run that had
        # already finished. Truncation is caught by the manifest's head and
        # count; this catches the opposite, something appended after the end.
        problems.append(
            f"{CHAIN_FILE}: {endings[0].type}@{endings[0].seq} ends the run but "
            f"{len(records) - 1 - records.index(endings[0])} record(s) follow it"
        )

    if contained:
        # Stopped, not completed. Whatever the agent had not done when it was
        # stopped is absent from this bundle, and absent is not clean. Reported
        # for every contained run, however the chain ends, because the operator
        # reading the verdict is the one who needs to know the run did not
        # finish — and because the alternative is a killed run verifying
        # identically to one that ran to completion.
        first = contained[0]
        reason = first.data.get("reason") or "unknown reason"
        detail = first.data.get("limit") or first.data.get("command") or ""
        incomplete_reasons.append(
            f"the run was stopped before it finished "
            f"({reason}{': ' + str(detail) if detail else ''}); whatever had "
            f"not happened yet is absent rather than clean"
        )

    errored = [r for r in endings if r.type == "run.error"]
    if errored:
        # Sealed deliberately, so not an integrity failure — but a run that
        # failed before it was under way never attested anything, and the
        # absence of those records is not evidence of a clean run.
        incomplete_reasons.append(
            f"the run ended in error before completing "
            f"({errored[0].data.get('message') or 'no message'}); whatever "
            f"had not happened yet is absent rather than clean"
        )

    # The field the guard protocol calls the finding that matters. It reached
    # the printed output and not the verdict, so a guard that reported a
    # non-exclusive route — or no attestation at all — still verified as OK.
    if egress_attested is False:
        problems.append(
            f"{CHAIN_FILE}: the guard did not attest as the sandbox's only "
            f"route, so the egress records are a lower bound rather than an "
            f"account of what the sandbox tried"
        )
    elif egress_attested is None and _expects_egress(records):
        incomplete_reasons.append(
            "a guard was started but never attested, so nothing establishes "
            "it was the sandbox's only route"
        )

    # The chain carries the numbers needed to detect records lost before the
    # seal, and ignoring them wasted the one cross-check the format has.
    problems.extend(_reconcile_close(records))

    # A control name outside the shared vocabulary means a writer and this
    # verifier have drifted, which is the failure the closed set exists to
    # prevent. Reported rather than sorted into a claim by guesswork.
    for name in attestation.unrecognised_controls(controls):
        incomplete_reasons.append(
            f"control {name!r} is not one this verifier recognises, so its "
            f"bearing on containment cannot be judged"
        )

    # Incomplete rather than failed, and the distinction is the whole point of
    # having four verdicts: every record in an unsigned bundle is still true,
    # and what is missing is attribution. A caller that wants this to be fatal
    # gets that from the exit status, since only `ok` exits 0.
    if require_signature and not signed:
        incomplete_reasons.append(
            "the bundle carries no signature, and this check required one, so "
            "nothing here establishes who produced it"
        )

    return VerifyResult(
        ok=not problems,
        records=len(records),
        head=head,
        problems=problems,
        signed=signed,
        signer_key_id=signer_key_id,
        signer_pinned=signer_pinned,
        egress_attested=egress_attested,
        egress_covers=egress_covers,
        complete=not incomplete_reasons,
        records_dropped=records_dropped,
        incomplete_reasons=incomplete_reasons,
        controls=controls,
        contained=not attestation.failed_controls(
            controls, attestation.CONTAINMENT
        ),
        governed_by=governed_by,
    )
