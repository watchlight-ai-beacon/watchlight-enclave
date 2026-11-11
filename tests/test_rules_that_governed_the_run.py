"""Whether the rules that governed a run held still while it ran.

Issue #18. ``config.attested`` recorded the digests of ``enclave.yaml`` and the
policy bundle once, when the chain opened. The docstring on
:meth:`Config.governing_digests` is right about the case it was written for —
a run that widens its *successor's* allowlist leaves the widening in its own
evidence — but there is a narrower one it did not cover.

``/policy`` is bound read-only, and it is the same inodes as
``/work/policies``, which is writable because an agent that cannot write code
cannot do the job. Nothing masks it. So a run can rewrite the rules it is
itself being held to, and a digest taken only at the start would go on
describing rules that stopped applying halfway through: the mechanism built to
make rule-tampering visible could not see tampering inside its own run.

The files are now read again at the end. Two readings that disagree are a
``problem``, not an incompleteness — nothing is missing, and the bundle is
making two statements about what the run was allowed to do that cannot both be
true.
"""

import hashlib
import pathlib
import tempfile

import pytest

from wl_enclave import config, evidence


IN_FORCE = {
    "controls": {
        name: {
            "in_force": True,
            "verified_by": "runtime_readback",
            "detail": "read back from the runtime",
        }
        for name in (
            "rootfs_read_only",
            "capabilities_dropped",
            "no_new_privileges",
            "runs_as_non_root",
            "evidence_masked_from_sandbox",
        )
    }
}


def digests(**files: str) -> dict:
    """A ``governing_digests()`` payload, combined exactly as config.py does."""
    combined = hashlib.sha256(
        "\n".join(f"{k}={v}" for k, v in sorted(files.items())).encode()
    ).hexdigest()
    return {"files": dict(files), "combined": f"sha256:{combined}"}


RULES = digests(**{"enclave.yaml": "sha256:aaa", "policy/a.policy.json": "sha256:bbb"})


def verdict_of(records):
    with tempfile.TemporaryDirectory() as tmp:
        bundle = pathlib.Path(tmp) / "bundle"
        chain = evidence.ChainWriter(bundle)
        for record_type, data in records:
            chain.append(record_type, data)
        chain.seal({"run": "t", "agent": "a", "runtime": "docker"})
        return evidence.verify(bundle)


def run_with(opened, closed=None):
    """A complete, otherwise clean run that read its rules once or twice."""
    records = [
        ("run.open", {}),
        ("sandbox.attested", IN_FORCE),
        ("config.attested", {"digests": opened}),
    ]
    if closed is not None:
        records.append(("config.reattested", {"digests": closed}))
    records.append(("run.close", {"exit_status": 0}))
    return verdict_of(records)


def test_rules_that_did_not_move_are_ok():
    """The baseline. Reading twice must not make an untouched run look guilty."""
    result = run_with(RULES, RULES)
    assert result.problems == [], result.problems
    assert result.verdict == "ok"


def test_a_policy_rewritten_mid_run_is_a_problem():
    """The issue itself: the agent edits the rules it is being judged by."""
    after = digests(
        **{"enclave.yaml": "sha256:aaa", "policy/a.policy.json": "sha256:WIDENED"}
    )
    result = run_with(RULES, after)
    assert result.verdict == "failed"
    assert any("rules changed while the run was under way" in p for p in result.problems)
    assert any("policy/a.policy.json was rewritten" in p for p in result.problems)


def test_enclave_yaml_rewritten_mid_run_is_a_problem():
    """The egress allowlist lives here, so this is the widening that matters."""
    after = digests(
        **{"enclave.yaml": "sha256:ZZZ", "policy/a.policy.json": "sha256:bbb"}
    )
    result = run_with(RULES, after)
    assert result.verdict == "failed"
    assert any("enclave.yaml was rewritten" in p for p in result.problems)


def test_a_policy_added_mid_run_is_named_as_added():
    """Being handed a new rule is not the same as rewriting an existing one.

    Both are reportable; a reviewer deciding how alarmed to be needs to know
    which happened, and a combined digest alone cannot say.
    """
    after = digests(
        **{
            "enclave.yaml": "sha256:aaa",
            "policy/a.policy.json": "sha256:bbb",
            "policy/b.policy.json": "sha256:ccc",
        }
    )
    result = run_with(RULES, after)
    assert result.verdict == "failed"
    assert any("policy/b.policy.json appeared during the run" in p for p in result.problems)


def test_a_policy_deleted_mid_run_is_named_as_removed():
    """Deleting the rule that forbids something is the cheapest way to widen."""
    after = digests(**{"enclave.yaml": "sha256:aaa"})
    result = run_with(RULES, after)
    assert result.verdict == "failed"
    assert any("policy/a.policy.json was removed during the run" in p for p in result.problems)


def test_a_bundle_with_only_one_reading_still_verifies():
    """Bundles written before the second reading existed must still verify.

    They hold no config.reattested at all. Treating a missing closing reading
    as a mismatch, or as something absent that should be there, would fail
    every bundle produced so far.
    """
    result = verdict_of(
        [
            ("run.open", {}),
            ("sandbox.attested", IN_FORCE),
            ("config.attested", {"digests": RULES}),
            ("run.close", {"exit_status": 0}),
        ]
    )
    assert result.verdict == "ok"
    assert result.governed_by == RULES["combined"]


def test_governed_by_reports_the_rules_the_run_started_under():
    """Not the closing ones.

    `governed_by` is what a gate pins to assert a run was governed by rules it
    recognises. Pointing it at the closing reading would let a run that
    rewrote its rules mid-flight satisfy a pin it never actually ran under.
    """
    after = digests(**{"enclave.yaml": "sha256:aaa", "policy/a.policy.json": "sha256:X"})
    result = run_with(RULES, after)
    assert result.governed_by == RULES["combined"]
    assert result.governed_by != after["combined"]


def test_an_unreadable_rule_file_is_reported_once_not_twice():
    """Reading twice must not say the same thing twice.

    An operator counting reasons should not learn that reading the files twice
    doubled the number of things wrong with the run.
    """
    broken = {
        "files": {"enclave.yaml": "sha256:aaa", "policy/a.policy.json": "unreadable: EACCES"},
        "combined": "sha256:same",
    }
    result = run_with(broken, broken)
    assert result.verdict == "incomplete"
    reasons = [r for r in result.incomplete_reasons if "cannot state what governed" in r]
    assert len(reasons) == 1, result.incomplete_reasons


def test_a_rule_restored_before_the_run_ended_is_not_caught():
    """The honest limit, pinned so no one later claims coverage this lacks.

    Two readings compare two points, not the interval between them. An agent
    that edits a rule file, acts under it and puts the original back produces
    two digests that agree, and this check sees nothing. Closing that needs a
    watch on the files rather than a second read, which is a different
    mechanism and a different issue.
    """
    result = run_with(RULES, RULES)
    assert result.verdict == "ok"
    assert result.problems == []


def test_governing_digests_actually_notices_an_edited_policy(tmp_path):
    """Against the real Config, not a hand-built payload.

    The records above are only as good as the digests that fill them, and the
    whole fix rests on `governing_digests()` returning something different
    after the bytes on disk change.
    """
    (tmp_path / "policies").mkdir()
    policy = tmp_path / "policies" / "a.policy.json"
    policy.write_text('[{"name": "n", "code": "permit(principal, action, resource);"}]')
    (tmp_path / "enclave.yaml").write_text(
        "version: 1\n"
        "agent:\n  name: a\n  command: [\"true\"]\n  image: busybox\n"
        "runtime: docker\npolicy: ./policies\n"
    )
    cfg = config.load(tmp_path / "enclave.yaml")

    opened = cfg.governing_digests()
    policy.write_text('[{"name": "n", "code": "permit(principal, action, resource);"}]  ')
    closed = cfg.governing_digests()

    assert opened["combined"] != closed["combined"]
    assert evidence._rules_that_moved(opened, closed) == ["policy/a.policy.json was rewritten"]


def test_the_policy_directory_is_inside_the_writable_workspace(tmp_path):
    """The premise the whole issue rests on, asserted rather than assumed.

    /work is bound writable and /policy read-only, but they are the same
    inodes: the read-only bind covers the path, not the files behind it. If a
    future change moves the policy bundle out of the workspace, this test
    should fail and the fix above can be reconsidered.
    """
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.policy.json").write_text(
        '[{"name": "n", "code": "permit(principal, action, resource);"}]'
    )
    (tmp_path / "enclave.yaml").write_text(
        "version: 1\n"
        "agent:\n  name: a\n  command: [\"true\"]\n  image: busybox\n"
        "runtime: docker\npolicy: ./policies\n"
    )
    cfg = config.load(tmp_path / "enclave.yaml")
    assert cfg.policy.resolve().is_relative_to(cfg.root.resolve())
