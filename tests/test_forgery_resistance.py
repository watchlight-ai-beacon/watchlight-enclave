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
from types import SimpleNamespace
import uuid
from pathlib import Path

import pytest

from wl_enclave import attestation, evidence, runs
from wl_enclave.cli import _mask_for_runs
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


def test_runs_inside_the_workspace_are_masked():
    masks = _mask_for_runs(Path("/proj"), Path("/proj/runs"))
    assert [m.target for m in masks] == ["/work/runs"]
    assert masks[0].masked is True
    assert masks[0].source is None


def test_a_runs_directory_outside_the_workspace_needs_no_mask():
    assert _mask_for_runs(Path("/proj"), Path("/elsewhere/runs")) == []


def test_a_nested_runs_directory_is_masked_at_its_real_depth():
    masks = _mask_for_runs(Path("/proj"), Path("/proj/var/runs"))
    assert [m.target for m in masks] == ["/work/var/runs"]


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
    """Seal a bundle from ``records``, ending it the way a real run does.

    A terminal record is appended unless the test supplies one, so each test's
    record list stays about the thing it is testing. verify() now requires a
    chain to say how its run ended — without that, a bundle holding only
    run.open verified as OK, which made the emptiest bundle the cleanest.
    """
    w = evidence.ChainWriter(tmp_path)
    for type_, data in records:
        w.append(type_, data)
    if not any(t in evidence._TERMINAL_RECORDS for t, _ in records):
        w.append("run.close", {"exit_status": 0})
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

    from wl_enclave.drivers import Mount, SandboxSpec

    spec = SandboxSpec(
        name="n", image="i", command=["c"],
        mounts=[Mount.bind(Path("/proj"), "/work"), Mount.mask("/work/runs")],
    )
    assert [m.target for m in spec.mounts if m.masked] == ["/work/runs"]


def test_a_mask_must_be_strictly_below_a_mount_target():
    """The invariant argv order does not provide.

    The daemon mounts by destination path length, so a mask equal to or
    shorter than a bind target collides with it rather than covering it. That
    would leave the path exposed while the spec claimed it was masked, so the
    driver refuses it instead of emitting it.
    """
    from wl_enclave.drivers import DriverError, Mount, SandboxSpec
    from wl_enclave.drivers.docker import DockerDriver

    with pytest.raises(DriverError, match="not strictly below"):
        SandboxSpec(
            name="n", image="python:3.12-slim", command=["true"],
            mounts=[
                Mount.bind(Path("/tmp"), "/work"),
                Mount.mask("/work"),  # equal to the bind target, not below it
            ],
        )


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

    with pytest.raises(DriverError):
        SandboxSpec(
            name="n", image="python:3.12-slim", command=["true"],
            mounts=[Mount.bind(Path("/tmp"), "/work"), Mount.mask(shadow)],
        )


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


# -- the canary must catch a mask the runtime reports but does not apply ---

@pytest.mark.skipif(
    shutil.which("docker") is None, reason="needs a container runtime"
)
def test_a_mask_the_daemon_records_but_does_not_apply_is_caught():
    """The case that proves configuration and effect are different questions.

    A tmpfs destination of "/work/." is accepted by the daemon, reported
    faithfully under HostConfig.Tmpfs, normalised onto the bind target, and
    masks nothing — the bind wins silently with no error. Every check based on
    the runtime's record of what was requested passes. Only reading a canary
    from inside the sandbox catches it.

    provision() now refuses this spec, so the container is created directly to
    reach the detection path the refusal protects.
    """
    from wl_enclave.drivers import Sandbox
    from wl_enclave.drivers.docker import DockerDriver

    project = Path.home() / f".wl-canary-probe-{uuid.uuid4().hex[:8]}"
    (project / "runs").mkdir(parents=True)
    # Planted at the host path the mask "/work/." actually resolves to, which
    # is the project root itself — the same derivation the driver makes.
    canary = project / ".wl-mask-canary-test"
    canary.write_text("this must not be readable from inside\n")
    driver = DockerDriver()
    container = ""
    try:
        proc = subprocess.run(
            [
                "docker", "run", "--detach", "--rm",
                "--tmpfs", "/work/.:rw,noexec,nosuid,size=1m",
                "--mount", f"type=bind,src={project.resolve()},dst=/work",
                "python:3.12-slim", "sleep", "30",
            ],
            capture_output=True, text=True, timeout=180,
        )
        if proc.returncode != 0:
            pytest.skip(f"could not create the probe container: {proc.stderr.strip()}")
        container = proc.stdout.strip()
        sandbox = Sandbox(id=container, name="probe", driver="docker")

        # What the runtime reports, and what is actually in force, disagree.
        inspected = json.loads(
            subprocess.run(
                ["docker", "inspect", container],
                capture_output=True, text=True, timeout=60,
            ).stdout
        )[0]
        tmpfs = (inspected.get("HostConfig") or {}).get("Tmpfs") or {}
        assert "/work/." in tmpfs, "the daemon did record the mask as requested"

        driver._masks[container] = ["/work/."]
        driver._canaries[container] = {"/work/./.wl-mask-canary-test": canary}
        control = driver._mask_control(sandbox, ["/work/."], [])

        assert control["in_force"] is False, control
        assert control["verified_by"] == "runtime_readback"
        assert "canary" in control["detail"]
    finally:
        if container:
            subprocess.run(
                ["docker", "kill", container], capture_output=True, timeout=60
            )
        shutil.rmtree(project, ignore_errors=True)


# -- mount coherence is a fact about the spec, not about one driver --------

def test_the_spec_derives_the_host_path_a_mask_hides():
    """The derivation moved onto the spec because the spec holds both halves.

    It used to live in the Docker driver, which meant a second driver either
    reimplemented it or quietly had no canary to plant — and a mask nobody can
    test is a mask nobody should claim.
    """
    from wl_enclave.drivers import Mount, SandboxSpec

    spec = SandboxSpec(
        name="n", image="i", command=["c"],
        mounts=[
            Mount.bind(Path("/proj"), "/work"),
            Mount.bind(Path("/other"), "/work/nested"),
            Mount.mask("/work/runs"),
            Mount.mask("/work/nested/deep"),
        ],
    )
    masks = {m.target: spec.host_path_behind(m) for m in spec.mounts if m.masked}
    assert masks["/work/runs"] == Path("/proj/runs")
    # The longest matching bind wins, not the first.
    assert masks["/work/nested/deep"] == Path("/other/deep")
    # A bind has nothing behind it.
    binds = [m for m in spec.mounts if not m.masked]
    assert spec.host_path_behind(binds[0]) is None


def test_incoherent_mounts_reports_every_problem_without_raising():
    """So a caller can report them all at once, the way config.load does."""
    from wl_enclave.drivers import Egress, Mount, SandboxSpec

    # Built field-by-field to bypass __post_init__, which is what a caller
    # wanting to report rather than raise would do.
    spec = SandboxSpec.__new__(SandboxSpec)
    object.__setattr__(spec, "egress", Egress.none())
    object.__setattr__(spec, "mounts", [
        Mount.bind(Path("/proj"), "/work"),
        Mount.mask("/work"),
        Mount.mask("relative/path"),
        Mount.mask("/work/runs/../../etc"),
    ])
    problems = spec.incoherent_mounts()
    assert len(problems) == 3
    assert any("not strictly below" in p for p in problems)
    assert any("not absolute" in p for p in problems)
    assert any("not normalised" in p for p in problems)


def test_a_mask_cannot_be_built_with_a_source():
    """`source is None` is the discriminant, so the constructors enforce it."""
    from wl_enclave.drivers import Mount

    assert Mount.mask("/work/runs").source is None
    assert Mount.mask("/work/runs").masked is True
    assert Mount.bind(Path("/proj"), "/work").masked is False
    # A mask is writable on purpose: the sandbox should see an empty directory
    # rather than a permission error it could mistake for its own bug.
    assert Mount.mask("/work/runs").read_only is False


# -- a chain is verified before it is extended -----------------------------

def test_an_edited_chain_cannot_be_extended(tmp_path):
    """The attack this closes.

    Appending to a chain resumes from its head. If that head is taken on
    trust, an attacker edits a record, appends anything, and seals — and the
    seal recomputes every hash from the edit onward so the result verifies
    cleanly. The one operation that would have caught the edit is the one that
    overwrites the evidence of it.
    """
    bundle = tmp_path / "bundle"
    chain = evidence.ChainWriter(bundle)
    chain.append("run.open", {"purpose": "original"})
    chain.append("decision", {"intent": "read", "resource": "/etc/passwd"})

    lines = (bundle / evidence.CHAIN_FILE).read_text().splitlines()
    edited = json.loads(lines[1])
    edited["data"]["resource"] = "/harmless"
    lines[1] = json.dumps(edited, sort_keys=True, separators=(",", ":"))
    (bundle / evidence.CHAIN_FILE).write_text("\n".join(lines) + "\n")

    with pytest.raises(evidence.BrokenChain, match="does not match its own content"):
        evidence.ChainWriter(bundle)


def test_a_reordered_chain_cannot_be_extended(tmp_path):
    bundle = tmp_path / "bundle"
    chain = evidence.ChainWriter(bundle)
    chain.append("run.open", {"purpose": "t"})
    chain.append("decision", {"n": 1})
    chain.append("decision", {"n": 2})

    path = bundle / evidence.CHAIN_FILE
    lines = path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(evidence.BrokenChain):
        evidence.ChainWriter(bundle)


def test_an_intact_chain_still_resumes(tmp_path):
    """The check must not cost the capability it protects.

    Sealing a partial bundle is how a contained run still produces evidence,
    so resuming has to keep working for every chain that does verify.
    """
    bundle = tmp_path / "bundle"
    first = evidence.ChainWriter(bundle)
    first.append("run.open", {"purpose": "t"})
    first.append("decision", {"n": 1})

    resumed = evidence.ChainWriter(bundle)
    resumed.append("run.contained", {"reason": "operator"})
    resumed.seal({"run": "r"})

    result = evidence.verify(bundle)
    assert result.ok is True
    assert result.records == 3


# -- egress intent is declared, so the driver can check it ----------------

def test_a_mediated_egress_must_name_a_network():
    """Intent that contradicts itself is refused where it is written."""
    from wl_enclave.drivers import DriverError, Egress, SandboxSpec

    with pytest.raises(DriverError, match="names no network"):
        SandboxSpec(
            name="n", image="i", command=["c"],
            egress=Egress(network="none", mediated=True),
        )


def test_an_endpoint_without_mediation_is_refused():
    """The combination that would attest a sandbox as governed when it is not.

    A sandbox pointed at a guard it is not *required* to go through looks
    identical, in a bundle, to one whose only route is that guard.
    """
    from wl_enclave.drivers import DriverError, Egress, SandboxSpec

    with pytest.raises(DriverError, match="not marked mediated"):
        SandboxSpec(
            name="n", image="i", command=["c"],
            egress=Egress(network="br0", endpoint="10.0.0.2:8080", mediated=False),
        )


def test_the_allowlist_travels_with_the_intent():
    """A bundle stating the topology without the policy describes half a boundary."""
    from wl_enclave.drivers import Egress

    e = Egress.mediated_by("wl-net", "10.0.0.2:8080", ["b.test:443", "a.test:443"])
    assert e.mediated is True
    assert e.allow == ("a.test:443", "b.test:443"), "sorted, so it is comparable"
    assert Egress.none().mediated is False
    assert Egress.none().network == "none"


# -- the mask claim must rest on a read that happened ----------------------

def test_an_unobservable_sandbox_cannot_attest_its_mask(monkeypatch):
    """The regression that mattered most in the third review.

    Every `docker exec` failing — a container that already exited, an image
    with no `cat`, exec refused — was read as "the canary was unreadable,
    therefore the mask holds". Combined with a mount table that could not be
    read either, the control returned in_force=True with the strongest
    provenance label in the vocabulary, from zero observation, and verify
    prints no detail for a control that is True.
    """
    from wl_enclave.drivers import Sandbox
    from wl_enclave.drivers.docker import DockerDriver

    driver = DockerDriver()
    sandbox = Sandbox(id="deadbeef", name="probe", driver="docker")
    driver._masks["deadbeef"] = ["/work/runs"]
    driver._canaries["deadbeef"] = {"/work/runs/.c": Path("/nonexistent/.c")}
    driver._witness["deadbeef"] = ("/work/.w", Path("/nonexistent/.w"))

    # Every probe fails the way exec does when it cannot run at all.
    monkeypatch.setattr(
        DockerDriver, "_run",
        lambda self, *a, **k: SimpleNamespace(returncode=126, stdout="", stderr="exec failed"),
    )
    control = driver._mask_control(sandbox, ["/work/runs"], [])

    assert control["in_force"] is None, control
    assert "could not be observed" in control["detail"]


def test_a_canary_hidden_but_exec_broken_is_not_a_confirmation(monkeypatch):
    """Exit codes, not truthiness.

    `cat` exits 1 for a file it cannot find — the mask working — and 126/127
    when exec itself failed, which says nothing about the file.
    """
    from wl_enclave.drivers import Sandbox
    from wl_enclave.drivers.docker import DockerDriver

    driver = DockerDriver()
    sandbox = Sandbox(id="c2", name="probe", driver="docker")
    driver._masks["c2"] = ["/work/runs"]
    driver._canaries["c2"] = {"/work/runs/.c": Path("/nonexistent/.c")}
    driver._witness["c2"] = ("/work/.w", Path("/nonexistent/.w"))

    def fake_run(self, *args, **kwargs):
        # The witness reads fine, so the sandbox IS observable; the canary
        # probe fails for an unrelated reason.
        if "/work/.w" in args:
            return SimpleNamespace(returncode=0, stdout="readable\n", stderr="")
        return SimpleNamespace(returncode=127, stdout="", stderr="cat: not found")

    monkeypatch.setattr(DockerDriver, "_run", fake_run)
    control = driver._mask_control(sandbox, ["/work/runs"], [])

    assert control["in_force"] is None, control
    assert "unrelated to the mask" in control["detail"]


# -- the sandbox owns evidence/ contents, so the host must not follow links -

def test_a_symlinked_audit_file_is_refused_not_followed(tmp_path):
    """Reproduces the third review's finding C.

    The sandbox owns the contents of evidence/, so it can replace the audit
    file with a symlink and have the trusted host read whatever it points at —
    a sibling bundle/chain.jsonl, which the sandbox is never supposed to reach.
    Bounded and field-filtered, so never a forgery primitive, but it made the
    documented boundary weaker for reads than runs.py claims it is.
    """
    from wl_enclave import runs

    secret = tmp_path / "chain.jsonl"
    secret.write_text(
        '{"decision": "Allow", "intent": "x", "resource": "y", "ts": "t"}\n'
    )
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    audit = evidence_dir / "audit.jsonl"
    audit.symlink_to(secret)

    records, account = runs.read_decisions(audit)
    assert records == [], "a symlinked audit file must not be read through"
    assert account["rejected_not_a_regular_file"] == 1


def test_a_real_audit_file_still_reads(tmp_path):
    """The check must not cost the capability it protects."""
    from wl_enclave import runs

    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        '{"decision": "Deny", "intent": "wire", "resource": "bank", "ts": "t"}\n'
    )
    records, account = runs.read_decisions(audit)
    assert len(records) == 1
    assert records[0]["asserted_by"] == "sandbox"
    assert account["rejected_not_a_regular_file"] == 0


def test_a_missing_audit_file_is_not_an_error(tmp_path):
    """An agent that made no governed calls writes nothing."""
    from wl_enclave import runs

    records, account = runs.read_decisions(tmp_path / "nope.jsonl")
    assert records == []
    assert account["rejected_not_a_regular_file"] == 0


# -- the sandbox never runs as root ---------------------------------------

def test_the_sandbox_user_is_never_uid_zero(monkeypatch):
    """Not left to the image.

    An image with no USER directive runs as uid 0, and most published base
    images have none — so this cannot be the image author's decision, who is
    frequently whoever we are trying to contain.
    """
    from wl_enclave.drivers import docker as docker_driver

    monkeypatch.setattr(docker_driver.os, "getuid", lambda: 501)
    monkeypatch.setattr(docker_driver.os, "getgid", lambda: 20)
    assert docker_driver._sandbox_user() == "501:20"

    # Mirroring the caller would put uid 0 in the container.
    monkeypatch.setattr(docker_driver.os, "getuid", lambda: 0)
    monkeypatch.setattr(docker_driver.os, "getgid", lambda: 0)
    assert docker_driver._sandbox_user() == "65532:65532"
    assert not docker_driver._sandbox_user().startswith("0:")


def test_a_root_sandbox_is_reported_as_uncontained(monkeypatch):
    """Read from inside, because Config.User is what was asked for.

    An entrypoint with the means can change uid after start, so `id -u` is the
    answer to the question a reviewer is actually asking.
    """
    from wl_enclave.drivers import Sandbox
    from wl_enclave.drivers.docker import DockerDriver

    driver = DockerDriver()
    sandbox = Sandbox(id="c", name="probe", driver="docker")
    monkeypatch.setattr(
        DockerDriver, "_run",
        lambda self, *a, **k: SimpleNamespace(returncode=0, stdout="0\n", stderr=""),
    )
    control = driver._user_control(sandbox, {})

    assert control["in_force"] is False
    assert control["verified_by"] == "runtime_readback"
    assert attestation.claim_of("runs_as_non_root") == attestation.CONTAINMENT
