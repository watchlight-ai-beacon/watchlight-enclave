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

import pytest

from wl_enclave.egress import Allowlist
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
