"""The egress attestation, against a real runtime.

These need Docker, because the whole point of an attestation is that it reads
the runtime rather than our own intentions. A mocked version of this test would
assert that the code agrees with itself, which is the thing being guarded
against.
"""

from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

from types import SimpleNamespace

import pytest

from wl_enclave.egress import Allowlist, GuardError
from wl_enclave.egress.local import LocalEgressGuard

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(["docker", "info"], capture_output=True).returncode != 0,
    reason="needs a running Docker daemon",
)

REPO = Path(__file__).resolve().parents[1]


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True)


@pytest.fixture
def guard(tmp_path_factory):
    # The record file must sit where the container runtime can bind-mount it;
    # under a VM-backed Docker, /tmp on the host is not necessarily shared.
    rec = REPO / "runs" / f"attest-{uuid.uuid4().hex[:8]}.jsonl"
    rec.parent.mkdir(parents=True, exist_ok=True)
    g = LocalEgressGuard()
    if g.preflight():
        pytest.skip("guard not buildable here")
    g.start(f"t{uuid.uuid4().hex[:8]}", Allowlist(["example.com:443"]), rec)
    yield g
    g.stop()
    rec.unlink(missing_ok=True)


@pytest.fixture
def sandbox(guard):
    name = f"wl-attest-{uuid.uuid4().hex[:8]}"
    proc = _docker("run", "-d", "--name", name, "--network", guard.network(),
                   "alpine:3.21", "sleep", "120")
    if proc.returncode != 0:
        pytest.skip(f"could not start a probe container: {proc.stderr.strip()[-120:]}")
    yield proc.stdout.strip()
    _docker("rm", "-f", name)


def test_a_sandbox_with_only_the_guard_network_attests(guard, sandbox):
    facts = guard.attest(sandbox)
    assert facts["network_internal"] is True
    assert facts["sandbox_networks"] == [guard.network()]
    # The guard needs the internal network AND a way out, or it cannot forward.
    assert guard.network() in facts["guard_networks"]
    assert len(facts["guard_networks"]) > 1
    assert facts["route_exclusive"] is True
    assert facts["problems"] == []


def test_a_second_route_on_the_sandbox_fails_attestation(guard, sandbox):
    """The mistake this exists to catch.

    A sandbox attached to a second network can reach the internet directly, so
    the proxy variables become advice and the egress records become a lower
    bound. The run must not be able to look fully mediated when it was not.
    """
    assert guard.attest(sandbox)["route_exclusive"] is True

    assert _docker("network", "connect", "bridge", sandbox).returncode == 0

    facts = guard.attest(sandbox)
    assert facts["route_exclusive"] is False
    assert "bridge" in facts["sandbox_networks"]
    assert any("not its only route" in p for p in facts["problems"])


def test_attestation_without_a_sandbox_reference_is_not_exclusive(guard):
    """Unknown must never read as safe."""
    facts = guard.attest(None)
    assert facts["route_exclusive"] is False
    assert any("not checked" in p for p in facts["problems"])


def test_attestation_with_no_guard_running_reports_no_route():
    facts = LocalEgressGuard().attest("whatever")
    assert facts["route_exclusive"] is False
    assert any("no guard network" in p for p in facts["problems"])


# -- a dead guard must fail the run, not produce a quiet bundle ------------

def test_the_ready_marker_matches_what_the_guard_prints():
    """String coupling between two languages, so assert it rather than hope.

    If the guard's startup message changes, the readiness wait would time out
    on a perfectly healthy guard and block every run with egress enabled.
    """
    from wl_enclave.egress.local import GUARD_READY_MARKER

    source = (REPO / "crates" / "wl-enclave-egress" / "src" / "main.rs").read_text()
    assert GUARD_READY_MARKER in source, (
        f"the guard no longer prints {GUARD_READY_MARKER!r}; the readiness "
        f"wait in local.py is coupled to it"
    )


def test_a_guard_that_exits_immediately_fails_the_start(tmp_path):
    """The failure that used to read as a clean run.

    `run --detach` returns once the container is created, so a guard that exits
    on startup still looked like a successful start. The run then proceeded with
    nothing listening: every connection refused by absence rather than by
    policy, no records written, and a bundle saying "attested, no attempts".

    Induced by substituting an image that exits as soon as it starts, which is
    what a guard refusing its own configuration looks like from outside.
    """
    rec = REPO / "runs" / f"dead-{uuid.uuid4().hex[:8]}.jsonl"
    rec.parent.mkdir(parents=True, exist_ok=True)
    if _docker("image", "inspect", "alpine:3.21").returncode != 0:
        if _docker("pull", "alpine:3.21").returncode != 0:
            pytest.skip("cannot obtain a substitute image")

    from wl_enclave.egress import local as local_mod

    g = LocalEgressGuard()
    if g.preflight():
        pytest.skip("guard not buildable here")
    original = local_mod.GUARD_IMAGE
    local_mod.GUARD_IMAGE = "alpine:3.21"  # runs /bin/sh with no input, exits
    try:
        with pytest.raises(GuardError) as exc:
            g.start(f"d{uuid.uuid4().hex[:8]}", Allowlist(["example.com:443"]), rec)
        message = str(exc.value)
        assert "exited immediately" in message or "bound listener" in message, message
    finally:
        local_mod.GUARD_IMAGE = original
        g.stop()
        rec.unlink(missing_ok=True)


# -- which build wrote the records ----------------------------------------

def test_the_announced_version_is_parsed_from_the_readiness_line():
    """Reuses the line the host already waits for, so the guard needs no
    second interface to be asked what it is."""
    from wl_enclave.egress.local import _announced_version

    ready = (
        "wl-enclave-egress 0.1.0: listening on 0.0.0.0:8080, "
        "1 allowlist rule(s), recording to /evidence/egress.jsonl"
    )
    assert _announced_version(ready) == "0.1.0"


def test_a_guard_that_announces_no_version_reports_none():
    """Empty, not a placeholder.

    An older guard printing no version is a fact worth seeing in a bundle, and
    a stand-in string would be indistinguishable from a guard that genuinely
    reported itself as that string.
    """
    from wl_enclave.egress.local import _announced_version

    assert _announced_version("wl-enclave-egress: listening on 0.0.0.0:8080") == ""
    assert _announced_version("") == ""


def test_an_unidentifiable_image_is_recorded_as_unreadable(monkeypatch):
    """Absent rather than guessed — an image we cannot identify is not the
    same as one we identified as missing."""
    from wl_enclave.egress.local import LocalEgressGuard

    guard = LocalEgressGuard()
    monkeypatch.setattr(
        LocalEgressGuard, "_run",
        lambda self, *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="no such image"),
    )
    facts = guard.build()

    assert facts["image_unreadable"] is True
    assert "image" not in facts
