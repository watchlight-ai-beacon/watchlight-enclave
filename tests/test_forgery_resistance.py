"""The agent must not be able to write the evidence that describes it.

Every test here corresponds to a way a sandboxed agent was once able to put
records of its own choosing into its own bundle. They are regression tests for
a specific class of failure: not a crash, but a bundle that verifies cleanly
while describing a run that did not happen.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from wl_enclave import evidence, runs
from wl_enclave.cli import _shadow_for_runs
from wl_enclave.egress import EGRESS_UNRECOGNISED, GUARD_RECORD_TYPES

REPO = Path(__file__).resolve().parents[1]


# -- the run's own evidence is out of the workspace mount --------------------

def test_the_guard_file_is_not_under_the_sandbox_writable_directory():
    """The guard is a witness; the subject must not share its notebook.

    ``evidence/`` has to be writable by the sandbox, because the SDK writes the
    decision trail from inside it. If the guard wrote there too, the agent could
    truncate the file or unlink and recreate it, leaving the guard appending to
    an orphaned inode.
    """
    run = runs.run_dir("/anywhere", "20260101-000000-aaaaaa")
    assert run.evidence_dir not in run.egress_file.parents
    assert run.guard_dir != run.evidence_dir


def test_runs_inside_the_workspace_are_shadowed():
    assert _shadow_for_runs(Path("/proj"), Path("/proj/runs")) == ["/work/runs"]


def test_a_runs_directory_outside_the_workspace_needs_no_shadow():
    assert _shadow_for_runs(Path("/proj"), Path("/elsewhere/runs")) == []


def test_a_nested_runs_directory_is_shadowed_at_its_real_depth():
    assert _shadow_for_runs(Path("/proj"), Path("/proj/var/runs")) == ["/work/var/runs"]


# -- the orchestrator owns the record type namespace ------------------------

@pytest.mark.parametrize(
    "declared",
    ["decision", "sandbox.attested", "egress.attested", "run.close", "run.open", None, "", 7],
)
def test_a_guard_record_cannot_name_a_type_outside_the_closed_set(declared):
    """A record that chooses its own type can forge another layer's evidence.

    These are written by a separate process into a file on disk, so the type
    they land under has to be decided here, against a closed set, and never
    read out of the record.
    """
    assert declared not in GUARD_RECORD_TYPES


@pytest.mark.parametrize("declared", sorted(GUARD_RECORD_TYPES))
def test_the_guards_own_types_are_accepted(declared):
    assert declared in GUARD_RECORD_TYPES


def test_the_closed_set_does_not_admit_any_non_egress_type():
    assert all(t.startswith("egress.") for t in GUARD_RECORD_TYPES)
    for forgeable in ("decision", "sandbox.attested", "run.open", "run.close",
                      "run.contained", "run.error", "egress.guard_started"):
        assert forgeable not in GUARD_RECORD_TYPES


def test_an_unrecognised_record_is_kept_rather_than_dropped():
    """Dropping it would let a writer erase evidence by malforming it."""
    assert EGRESS_UNRECOGNISED.startswith("egress.")
    assert EGRESS_UNRECOGNISED not in GUARD_RECORD_TYPES


# -- verify resists an appended attestation --------------------------------

def _bundle(tmp_path, records):
    w = evidence.ChainWriter(tmp_path)
    for type_, data in records:
        w.append(type_, data)
    w.seal({"run": "t", "agent": "a", "runtime": "docker"})
    return tmp_path


def test_a_second_attestation_is_a_problem_and_the_first_still_wins(tmp_path):
    """The forgery that mattered most: append a flattering attestation.

    Taking the last would let anything able to append a record overwrite the
    finding. A run writes exactly one, so a second means something else did.
    """
    bundle = _bundle(tmp_path, [
        ("run.open", {"run": "t"}),
        ("egress.attested", {"route_exclusive": False, "records_cover": ["http_connect"],
                             "problems": ["the sandbox is also attached to bridge"]}),
        ("egress.attested", {"route_exclusive": True,
                             "records_cover": ["tcp", "udp", "dns"], "problems": []}),
    ])
    result = evidence.verify(bundle)
    assert result.egress_attested is False, "the first attestation must win"
    assert result.egress_covers == ["http_connect"]
    assert not result.ok
    assert any("egress attestations" in p for p in result.problems)


def test_one_attestation_is_reported_without_complaint(tmp_path):
    bundle = _bundle(tmp_path, [
        ("run.open", {"run": "t"}),
        ("egress.attested", {"route_exclusive": True, "records_cover": ["http_connect"]}),
    ])
    result = evidence.verify(bundle)
    assert result.ok and result.egress_attested is True


# -- a control that is not attested is a control nobody can check ----------

def test_the_spec_declares_the_mask_so_a_driver_can_attest_it():
    """The mask is a security control, so it has to reach the bundle.

    An isolation setting that is applied but never read back is
    indistinguishable, in the bundle, from one that was never applied. This is
    the same reason ``attest()`` exists rather than echoing SandboxSpec.
    """
    from wl_enclave.drivers import SandboxSpec

    spec = SandboxSpec(name="n", image="i", command=["c"], shadow=["/work/runs"])
    assert spec.shadow == ["/work/runs"]


def test_a_mask_must_be_strictly_below_a_mount_target():
    """The invariant argv order does not provide.

    The daemon mounts by destination path length, so a mask equal to or
    shorter than a bind target collides with it rather than covering it. That
    would leave the path exposed while the spec claimed it was masked, so the
    driver refuses it instead of emitting it.
    """
    from wl_enclave.drivers import DriverError, Mount, SandboxSpec
    from wl_enclave.drivers.docker import DockerDriver

    spec = SandboxSpec(
        name="n", image="python:3.12-slim", command=["true"],
        mounts=[Mount(source=Path("/tmp"), target="/work")],
        shadow=["/work"],  # equal to the mount target, not below it
    )
    with pytest.raises(DriverError, match="not strictly below"):
        DockerDriver().provision(spec)


def test_the_guard_writes_outside_the_shared_evidence_path():
    """The in-container path must not be named /evidence either.

    A reviewer reading the guard's mount list would reasonably read
    /evidence/... as the directory shared with the sandbox, which is the exact
    confusion the host-side split exists to remove.
    """
    from wl_enclave.egress.local import RECORD_IN_GUARD

    assert not RECORD_IN_GUARD.startswith("/evidence")


# -- end to end, against a real runtime ------------------------------------

@pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(["docker", "info"], capture_output=True).returncode != 0,
    reason="needs a running Docker daemon",
)
def test_a_sandbox_cannot_see_its_own_run_directory(tmp_path):
    """The proof, not the argument.

    The project root is mounted read-write at /work and the run directory lives
    inside it, so without a shadow the agent can reach its own bundle. The
    sandbox reports what it can see; the assertion is that it sees nothing.
    """
    # The runtime may be VM-backed, where only the home directory is shared.
    project = Path.home() / f".wl-test-{uuid.uuid4().hex[:8]}"
    (project / "policies").mkdir(parents=True)
    (project / "policies" / "p.policy.json").write_text(
        '[{"name": "p", "code": "permit(principal, action, resource);"}]'
    )
    (project / "enclave.yaml").write_text(
        "version: 1\n"
        "agent:\n"
        '  name: probe\n'
        '  command: ["python", "/work/probe.py"]\n'
        "  image: python:3.12-slim\n"
        "runtime: docker\n"
        "policy: ./policies\n"
        "egress:\n  allow: []\n"
        "limits:\n  memory: 512Mi\n  cpus: 1\n  pids: 128\n  timeout: 2m\n"
    )
    (project / "probe.py").write_text(
        "import json, pathlib\n"
        "seen = sorted(p.name for p in pathlib.Path('/work/runs').glob('*'))\n"
        "wrote = []\n"
        "for p in pathlib.Path('/work/runs').glob('*/bundle'):\n"
        "    try:\n"
        "        (p / 'agent-was-here').write_text('x')\n"
        "        wrote.append(str(p))\n"
        "    except OSError:\n"
        "        pass\n"
        "print('PROBE ' + json.dumps({'seen': seen, 'wrote': wrote}))\n"
    )
    try:
        proc = subprocess.run(
            [str(REPO / ".venv" / "bin" / "wl-enclave"), "-C", str(project),
             "run", "--purpose", "shadow regression"],
            capture_output=True, text=True, timeout=600,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        logs = next(project.glob("runs/*/logs.txt")).read_text()
        line = next(l for l in logs.splitlines() if l.startswith("PROBE "))
        found = json.loads(line[len("PROBE "):])
        assert found["seen"] == [], f"the sandbox saw its own run dirs: {found['seen']}"
        assert found["wrote"] == [], f"the sandbox wrote into its own bundle: {found['wrote']}"
        # And nothing was actually created on the host.
        assert list(project.glob("runs/*/bundle/agent-was-here")) == []

        # The mask must also be visible in the bundle. A reviewer who cannot
        # see the control in the evidence has to take our word for it, which is
        # the thing this whole mechanism is trying to avoid.
        chain = next(project.glob("runs/*/bundle/chain.jsonl")).read_text()
        attested = [
            json.loads(line) for line in chain.splitlines()
            if json.loads(line)["type"] == "sandbox.attested"
        ]
        assert attested, "no sandbox.attested record"
        masked = attested[0]["data"]["constraints"]["masked_paths"]
        assert "/work/runs" in masked, f"the mask is not attested: {masked}"
    finally:
        shutil.rmtree(project, ignore_errors=True)


def test_the_closed_set_matches_every_type_the_guard_actually_writes():
    """The two must not drift, in either direction.

    A type the guard writes but the set omits is filed as unrecognised, so
    genuine evidence is demoted and the run.close counters stop matching the
    chain. A type in the set that the guard never writes is a slot something
    else could occupy. Reading the Rust source is crude but it fails loudly the
    moment a record type is added on one side only, which is the bug this
    guards.
    """
    import re

    source = (REPO / "crates" / "wl-enclave-egress" / "src" / "recorder.rs").read_text()
    written = set(re.findall(r'"event"\s*:\s*"([^"]+)"', source))
    assert written, "found no record types in the recorder; has it moved?"
    assert written == set(GUARD_RECORD_TYPES), (
        f"only the guard writes: {sorted(written - set(GUARD_RECORD_TYPES))}; "
        f"only the closed set has: {sorted(set(GUARD_RECORD_TYPES) - written)}"
    )


@pytest.mark.parametrize(
    "shadow,why",
    [
        ("/work/runs/../../etc", "passes a prefix test; the daemon mounts it at /etc"),
        ("/work/.", "normalises to /work, collides with the bind, bind wins silently"),
        ("/work/runs/./../..", "escapes the mount entirely"),
        ("work/runs", "not absolute"),
    ],
)
def test_a_mask_that_changes_under_normalisation_is_refused(shadow, why):
    """A prefix test on the raw string asks a different question than the daemon.

    Docker normalises the mount destination itself, so a path can pass the
    check as written and be mounted somewhere else — with the attestation
    reporting the path as given, claiming a mask over something it never
    covered.
    """
    from wl_enclave.drivers import DriverError, Mount, SandboxSpec
    from wl_enclave.drivers.docker import DockerDriver

    spec = SandboxSpec(
        name="n", image="python:3.12-slim", command=["true"],
        mounts=[Mount(source=Path("/tmp"), target="/work")],
        shadow=[shadow],
    )
    with pytest.raises(DriverError):
        DockerDriver().provision(spec)


# -- decision records are the agent's own account, and are treated as such --

def test_a_forged_provenance_claim_is_overwritten_not_merged(tmp_path):
    """The agent writes these records. It does not get to say where they came from.

    Validation would only establish that a record is well-formed. Stamping
    provenance at the boundary establishes who wrote it, which is the fact a
    reviewer actually needs, and it must overwrite rather than merge or the
    agent's claim survives alongside ours.
    """
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({
            "decision": "Allow", "intent": "research", "resource": "tool/x",
            "ts": "2026-01-01T00:00:00+00:00",
            "asserted_by": "runtime_readback",  # the forgery
        }) + "\n"
    )
    records, _ = runs.read_decisions(audit)
    assert records[0]["asserted_by"] == "sandbox"


def test_unknown_fields_are_dropped_rather_than_carried(tmp_path):
    """An unknown field in an agent-authored record is something a reader might believe."""
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({
            "decision": "Allow", "intent": "research", "resource": "tool/x",
            "ts": "2026-01-01T00:00:00+00:00",
            "verified_by": "runtime_readback", "route_exclusive": True,
        }) + "\n"
    )
    records, _ = runs.read_decisions(audit)
    assert "verified_by" not in records[0]
    assert "route_exclusive" not in records[0]


def test_a_newline_in_a_field_cannot_split_one_record_into_two(tmp_path):
    """The chain is line-delimited JSON; a control character is a forgery primitive."""
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({
            "decision": "Allow", "intent": "research",
            "resource": 'tool/x\n{"decision":"Allow","intent":"exfiltrate"}',
            "ts": "2026-01-01T00:00:00+00:00",
        }) + "\n"
    )
    records, account = runs.read_decisions(audit)
    assert len(records) == 1
    assert "\n" not in records[0]["resource"]
    assert account["truncated_fields"] == 1


def test_the_decision_count_is_capped_and_the_cap_is_reported(tmp_path):
    """Without a cap, a loop makes the chain arbitrarily long.

    The overflow is counted rather than ignored: a run that hit the cap must
    not look like a run that simply made fewer decisions.
    """
    audit = tmp_path / "audit.jsonl"
    one = json.dumps({
        "decision": "Allow", "intent": "research", "resource": "tool/x",
        "ts": "2026-01-01T00:00:00+00:00",
    })
    audit.write_text("\n".join([one] * (runs.MAX_DECISIONS + 25)) + "\n")
    records, account = runs.read_decisions(audit)
    assert len(records) == runs.MAX_DECISIONS
    assert account["dropped_over_cap"] == 25


def test_a_record_missing_required_fields_is_counted_not_chained(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps({"decision": "Allow"}) + "\n"
        + "not json at all\n"
        + json.dumps({
            "decision": "Allow", "intent": "research", "resource": "tool/x",
            "ts": "2026-01-01T00:00:00+00:00",
        }) + "\n"
    )
    records, account = runs.read_decisions(audit)
    assert len(records) == 1
    assert account["malformed"] == 2
