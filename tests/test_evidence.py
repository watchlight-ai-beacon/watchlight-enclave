"""The evidence chain: tamper detection, and what verify reports."""

from __future__ import annotations

import json

import pytest

from wl_enclave import evidence


def build(tmp_path, records):
    w = evidence.ChainWriter(tmp_path)
    for type_, data in records:
        w.append(type_, data)
    w.seal({"run": "t", "agent": "a", "runtime": "docker"})
    return tmp_path


RUN = [("run.open", {"run": "t"}), ("decision", {"verdict": "Deny"})]


def test_an_untouched_bundle_verifies(tmp_path):
    r = evidence.verify(build(tmp_path, RUN))
    assert r.ok and r.records == 2 and r.problems == []


def test_an_edited_record_is_caught(tmp_path):
    bundle = build(tmp_path, RUN)
    path = bundle / evidence.CHAIN_FILE
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["data"]["verdict"] = "Allow"
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    r = evidence.verify(bundle)
    assert not r.ok
    assert any("does not match its content" in p for p in r.problems)


def test_a_record_removed_from_the_end_is_caught_by_the_manifest(tmp_path):
    """Truncation is the cheapest attack: drop the records you dislike.

    The chain alone cannot see it — a shorter chain is still internally
    consistent — so the manifest pins the head and the count.
    """
    bundle = build(tmp_path, RUN)
    path = bundle / evidence.CHAIN_FILE
    lines = path.read_text().splitlines()
    path.write_text(lines[0] + "\n")

    r = evidence.verify(bundle)
    assert not r.ok
    assert any("manifest" in p.lower() for p in r.problems)


def test_a_recomputed_chain_verifies_which_is_why_signing_matters(tmp_path):
    """An expected pass, recorded deliberately.

    A forger who edits a record and then recomputes every following hash *and*
    the manifest produces a bundle that verifies. This is the documented limit
    of an unsigned chain, not a bug: the chain establishes internal
    consistency, never origin. If this test ever fails, signing has landed and
    the claim in :mod:`wl_enclave.evidence` needs revisiting.
    """
    bundle = build(tmp_path, RUN)
    path = bundle / evidence.CHAIN_FILE
    records = [json.loads(l) for l in path.read_text().splitlines()]
    records[1]["data"]["verdict"] = "Allow"

    prev = evidence.GENESIS
    for rec in records:
        rec["prev"] = prev
        rec["hash"] = evidence.Record.digest(
            rec["seq"], rec["ts"], rec["type"], rec["data"], prev
        )
        prev = rec["hash"]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    manifest = json.loads((bundle / evidence.MANIFEST_FILE).read_text())
    manifest["head"] = prev
    (bundle / evidence.MANIFEST_FILE).write_text(json.dumps(manifest))

    r = evidence.verify(bundle)
    assert r.ok, "an unsigned chain cannot detect a fully recomputed forgery"
    assert not r.signed


@pytest.mark.parametrize(
    "exclusive,expected",
    [(True, True), (False, False)],
)
def test_verify_reports_the_egress_attestation(tmp_path, exclusive, expected):
    bundle = build(
        tmp_path,
        RUN + [("egress.attested", {"route_exclusive": exclusive, "problems": []})],
    )
    assert evidence.verify(bundle).egress_attested is expected


def test_a_bundle_with_no_guard_claims_nothing_about_egress(tmp_path):
    """``None``, not ``False``: no guard ran, so there is nothing to report.

    Reporting False here would tell a reviewer the guard was bypassed, which is
    a different and more alarming statement than "no guard was configured".
    """
    assert evidence.verify(build(tmp_path, RUN)).egress_attested is None


# -- a bundle the guard calls incomplete must not verify as OK ------------

def test_a_suppression_note_makes_the_bundle_incomplete_not_failed(tmp_path):
    """Three states, not two.

    An intact chain and a complete one are different claims. A run that hit a
    rate limit must not read "OK", and must not read "FAILED" either — that
    would be indistinguishable from a tampered chain and would train a reviewer
    to ignore it.
    """
    bundle = tmp_path / "bundle"
    chain = evidence.ChainWriter(bundle)
    chain.append("run.open", {"purpose": "t"})
    chain.append("egress.attempt", {"host": "example.com", "port": 443, "verdict": "allow"})
    chain.append(
        "egress.records_suppressed",
        {"reason": "per-run record limit reached", "records_dropped": 4096},
    )
    chain.append("run.close", {"exit_code": 0})
    chain.seal({"agent": "t"})

    result = evidence.verify(bundle)
    assert result.ok is True, "the chain itself is intact"
    assert result.complete is False
    assert result.records_dropped == 4096
    assert result.verdict == "incomplete"
    assert "INCOMPLETE" in result.summary
    assert "1 reason" in result.summary
    assert any("4096" in r for r in result.incomplete_reasons)


def test_a_clean_bundle_is_complete(tmp_path):
    bundle = tmp_path / "bundle"
    chain = evidence.ChainWriter(bundle)
    chain.append("run.open", {"purpose": "t"})
    chain.append("run.close", {"exit_code": 0})
    chain.seal({"agent": "t"})

    result = evidence.verify(bundle)
    assert (result.ok, result.complete, result.verdict) == (True, True, "ok")
    assert result.summary.startswith("OK")


def test_a_guard_that_stopped_early_makes_the_bundle_incomplete(tmp_path):
    """The other way the egress records become a lower bound.

    Not records dropped under a limit, but records never taken, because nothing
    was watching. A guard that died mid-run leaves a file that looks merely
    quiet, and the attestation was taken at provision time — too early to
    notice.
    """
    bundle = tmp_path / "bundle"
    chain = evidence.ChainWriter(bundle)
    chain.append("run.open", {"purpose": "t"})
    chain.append("egress.attested", {"route_exclusive": True, "records_cover": ["http_connect"]})
    chain.append("egress.guard_stopped", {"guard_running": False, "guard_exit_code": 137})
    chain.append("run.close", {"exit_code": 0})
    chain.seal({"agent": "t"})

    result = evidence.verify(bundle)
    assert result.complete is False
    assert result.verdict == "incomplete"
    assert any("stopped before the run ended" in r for r in result.incomplete_reasons)
    assert result.problems == [], "a dead guard is not an integrity failure"
    # Attested and complete are different claims: the topology really was
    # exclusive, and the records are still an understatement.
    assert result.egress_attested is True
