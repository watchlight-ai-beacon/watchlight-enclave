"""What a chain's ending says, and what the verdict makes of it.

Issue #35. ``verify`` asked how many terminal records a chain held and required
exactly one. That counted two different things as the same thing, and was wrong
in both directions.

A run stopped by its timeout records ``run.contained`` and then seals with
``run.close`` and its tallies, because it genuinely did both. Counting gave two
endings and FAILED a bundle that was sound — a verifier refusing evidence that
is fine.

The other direction mattered more. A run killed by an operator, whose chain ends
at ``run.contained`` because nothing came along to close it, counted as one
ending and verified ``ok``: the same verdict as a run that finished. A bundle
that understates what happened is the one thing this format exists to prevent.

The rule now distinguishes *ending* the run (``run.close`` / ``run.error``, at
most one, and last) from *being stopped* (``run.contained``, which may be last
but is never clean).
"""

import pathlib
import tempfile

import pytest

from wl_enclave import evidence


#: Enough real controls, all in force, that nothing else drags the verdict off
#: ``ok``. A name this verifier does not recognise is itself a reason for
#: ``incomplete``, which would mask what these tests are about.
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

ATTESTED = [("run.open", {}), ("sandbox.attested", IN_FORCE)]


def verdict_of(records):
    """Seal a chain of these records and verify it."""
    with tempfile.TemporaryDirectory() as tmp:
        bundle = pathlib.Path(tmp) / "bundle"
        chain = evidence.ChainWriter(bundle)
        for record_type, data in records:
            chain.append(record_type, data)
        chain.seal({"run": "t", "agent": "a", "runtime": "docker"})
        return evidence.verify(bundle)


def test_a_completed_run_is_ok():
    """The baseline the others are measured against."""
    result = verdict_of(ATTESTED + [("run.close", {"exit_status": 0})])
    assert result.verdict == "ok"
    assert result.problems == []


def test_a_timed_out_run_verifies_instead_of_failing():
    """The bug as filed: a sound bundle was refused.

    The timeout path contains the sandbox and then seals normally, so the chain
    holds run.contained *and* run.close. Both are true, and neither is missing.
    """
    result = verdict_of(
        ATTESTED
        + [
            ("run.contained", {"reason": "timeout", "limit": "20s"}),
            ("run.close", {"exit_status": None}),
        ]
    )
    assert result.problems == [], result.problems
    assert result.verdict == "incomplete"


def test_a_killed_run_does_not_verify_the_same_as_one_that_finished():
    """The half that mattered, and the reason this is not only a false alarm.

    `wl-enclave kill` appends run.contained to a chain that nothing will close.
    That used to be a single terminal record and an `ok` verdict, which is a
    bundle understating what happened: the agent was stopped, and whatever it
    had not done is absent rather than clean.
    """
    result = verdict_of(
        ATTESTED + [("run.contained", {"reason": "operator", "command": "kill"})]
    )
    assert result.verdict == "incomplete"
    assert result.verdict != "ok"
    assert any("stopped before it finished" in r for r in result.incomplete_reasons)


@pytest.mark.parametrize(
    "reason,detail,shown",
    [
        ({"reason": "timeout", "limit": "20s"}, "limit", "timeout: 20s"),
        ({"reason": "operator", "command": "quarantine"}, "command", "operator: quarantine"),
    ],
)
def test_the_verdict_says_why_the_run_was_stopped(reason, detail, shown):
    """An operator reading `incomplete` needs to know which kind of stop."""
    result = verdict_of(ATTESTED + [("run.contained", reason)])
    assert any(shown in r for r in result.incomplete_reasons), result.incomplete_reasons


def test_a_chain_that_never_says_how_it_ended_still_fails():
    """The check's original job, unchanged.

    Without it the shortest bundle is the cleanest, which inverts the whole
    format: a run that died early would produce tidier evidence than one that
    completed.
    """
    result = verdict_of(ATTESTED)
    assert result.verdict == "failed"
    assert any("does not say how the run ended" in p for p in result.problems)


def test_two_endings_still_fail():
    """Relaxing run.contained must not relax run.close."""
    result = verdict_of(
        ATTESTED + [("run.close", {"exit_status": 0}), ("run.close", {"exit_status": 0})]
    )
    assert result.verdict == "failed"
    assert any("end the run, but a run ends once" in p for p in result.problems)


def test_records_after_the_ending_are_refused():
    """Newly caught, and previously silent.

    A chain whose run.close is followed by more records describes a run that had
    already ended. The old rule counted one terminal record and returned `ok`.
    Truncation from the end is caught by the manifest's head and count; this is
    the opposite case, and nothing was looking for it.
    """
    result = verdict_of(
        ATTESTED
        + [
            ("run.close", {"exit_status": 0}),
            ("decision", {"action": "x", "effect": "allow"}),
        ]
    )
    assert result.verdict == "failed"
    assert any("record(s) follow it" in p for p in result.problems)


def test_a_run_that_errored_is_still_incomplete():
    """Unchanged by the rewrite, and worth pinning because it moved in the code."""
    result = verdict_of(
        [("run.open", {}), ("run.error", {"message": "egress guard: boom"})]
    )
    assert result.verdict == "incomplete"
    assert any("ended in error" in r for r in result.incomplete_reasons)


def test_contained_and_errored_are_reported_separately():
    """Two different gaps, so two reasons. Collapsing them loses one."""
    result = verdict_of(
        [
            ("run.open", {}),
            ("run.contained", {"reason": "timeout", "limit": "1s"}),
            ("run.error", {"message": "sealing after a stop"}),
        ]
    )
    assert result.verdict == "incomplete"
    assert any("stopped before it finished" in r for r in result.incomplete_reasons)
    assert any("ended in error" in r for r in result.incomplete_reasons)
