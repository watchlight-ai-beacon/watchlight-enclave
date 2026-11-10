"""``wl-enclave hosts`` — the command that answers "what did it reach?".

The property worth testing is not the table. It is that a bundle which does not
verify is excluded *and* announced: a shorter, tidier host list is the one way
this command could mislead, and it is the direction the whole format exists to
rule out.
"""

from __future__ import annotations

import argparse

from wl_enclave import cli, evidence


def _run_with(root, run_id, attempts, *, attested=True, terminal="run.close"):
    """A run directory on disk whose bundle verifies as ok."""
    bundle = root / "runs" / run_id / "bundle"
    bundle.mkdir(parents=True)
    chain = evidence.ChainWriter(bundle)
    chain.append("run.open", {"purpose": "t"})
    if attested:
        chain.append(
            "egress.attested",
            {
                "route_exclusive": True,
                "records_cover": ["http_connect"],
                "blocked_not_recorded": ["raw_tcp", "udp", "icmp"],
            },
        )
    for host, verdict, sent in attempts:
        chain.append(
            "egress.attempt",
            {
                "host": host,
                "port": 443,
                "verdict": verdict,
                "protocol": "connect",
                **({"resolved_ip": "203.0.113.7"} if verdict == "allow" else {}),
            },
        )
        if verdict == "allow":
            chain.append(
                "egress.tunnel",
                {
                    "host": host,
                    "port": 443,
                    "bytes_sent": sent,
                    "bytes_received": sent * 2,
                    "outcome": "closed",
                },
            )
    chain.append(terminal, {})
    chain.seal({"run": run_id, "agent": "a", "runtime": "docker"})
    return bundle


def _hosts(root, **kw):
    return cli._cmd_hosts(argparse.Namespace(directory=str(root), since=None, **kw))


def test_it_aggregates_attempts_across_runs(tmp_path, capsys):
    _run_with(tmp_path, "20261103-100000-aaaaaa", [("example.com", "allow", 100)])
    _run_with(
        tmp_path,
        "20261104-100000-bbbbbb",
        [("example.com", "allow", 100), ("pastebin.com", "deny", 0)],
    )

    assert _hosts(tmp_path) == 0
    out = capsys.readouterr().out
    assert "2 verified" in out
    assert "EXCLUDED" not in out
    assert "example.com" in out and "pastebin.com" in out
    # Two allow attempts folded into one row, and the bytes summed across runs.
    assert "200 B" in out  # 2 x 100 sent
    assert "400 B" in out  # 2 x 200 received
    assert "203.0.113.7" in out
    assert "over 3 attempt(s)" in out


def test_coverage_is_printed_beside_the_answer(tmp_path, capsys):
    _run_with(tmp_path, "20261103-100000-aaaaaa", [("example.com", "allow", 10)])
    _hosts(tmp_path)
    out = capsys.readouterr().out
    assert "http_connect only" in out
    assert "had no route and are not recorded" in out


def test_a_bundle_that_does_not_verify_is_excluded_and_announced(tmp_path, capsys):
    _run_with(tmp_path, "20261103-100000-aaaaaa", [("example.com", "allow", 10)])
    broken = _run_with(tmp_path, "20261104-100000-bbbbbb", [("evil.test", "allow", 10)])
    # Edit a record so the chain no longer verifies.
    path = broken / "chain.jsonl"
    path.write_text(path.read_text().replace("evil.test", "innocent.test"))

    code = _hosts(tmp_path)
    out = capsys.readouterr().out

    # Excluded: neither the real host nor the substituted one is reported, so
    # the table cannot be read as an account of that run.
    assert "evil.test" not in out
    assert "innocent.test" not in out
    # Announced: the reader is told a run's hosts are missing from the table.
    assert "1 EXCLUDED" in out
    assert "are NOT in this table" in out
    # And non-zero, so a gate cannot pass on a tidy table beside a bad bundle.
    assert code == 1


def test_an_incomplete_run_makes_the_list_a_lower_bound(tmp_path, capsys):
    # A run that ended in error is incomplete by its own account: whatever had
    # not happened yet is absent rather than clean.
    _run_with(
        tmp_path,
        "20261103-100000-aaaaaa",
        [("example.com", "allow", 10)],
        terminal="run.error",
    )
    code = _hosts(tmp_path)
    out = capsys.readouterr().out
    assert "lower bound" in out
    assert code == 1


def test_since_filters_by_the_date_in_the_run_id(tmp_path, capsys):
    _run_with(tmp_path, "20261103-100000-aaaaaa", [("old.test", "allow", 10)])
    _run_with(tmp_path, "20261105-100000-bbbbbb", [("new.test", "allow", 10)])

    cli._cmd_hosts(
        argparse.Namespace(directory=str(tmp_path), since="2026-11-05")
    )
    out = capsys.readouterr().out
    assert "new.test" in out
    assert "old.test" not in out


def test_a_since_that_is_not_a_date_is_refused(tmp_path, capsys):
    assert (
        cli._cmd_hosts(argparse.Namespace(directory=str(tmp_path), since="last tuesday"))
        == 1
    )


def test_no_runs_is_not_an_error(tmp_path, capsys):
    assert _hosts(tmp_path) == 0
    assert "no runs" in capsys.readouterr().out
