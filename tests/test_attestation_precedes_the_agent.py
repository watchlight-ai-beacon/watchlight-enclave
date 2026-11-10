"""The agent must not run until its containment has been attested.

Issue #22. ``provision`` used to create the container with the agent as its
first process, so the agent was already running by the time ``attest`` read the
boundary back. Two things followed. On a fast host the agent could finish first
and the attestation described a container that no longer existed, which read as
an unobservable sandbox and an ``INCOMPLETE`` verdict on a healthy run. Worse,
the check that establishes the agent cannot reach its own evidence ran after the
agent had already had the chance to reach it.

These tests pin the ordering without needing a container runtime: the end-to-end
job exercises the real thing, but it only runs where Docker does, and the
property is cheap to assert directly.
"""

import subprocess
from pathlib import Path

import pytest

from wl_enclave.drivers import DriverError, Mount, Sandbox, SandboxSpec
from wl_enclave.drivers.docker import _HOLD_COMMAND, DockerDriver


AGENT_COMMAND = ["python", "agent.py"]


def _spec() -> SandboxSpec:
    return SandboxSpec(
        name="wl-enclave-test",
        image="python:3.12-slim",
        command=list(AGENT_COMMAND),
        mounts=[Mount.bind(Path("/proj"), "/work"), Mount.mask("/work/runs")],
    )


class _FakeDocker:
    """Stands in for the docker CLI, recording what it was asked to do."""

    def __init__(self, running: str = "true") -> None:
        self.calls: list[tuple[str, ...]] = []
        self.running = running

    def __call__(self, *args: str, timeout=None, check=True):
        self.calls.append(args)
        out = ""
        if args[0] == "run":
            out = "c0ffee1234"
        elif args[0] == "inspect":
            out = self.running
        return subprocess.CompletedProcess(list(args), 0, stdout=out, stderr="")

    def argv_of(self, verb: str) -> tuple[str, ...]:
        for call in self.calls:
            if call[0] == verb:
                return call
        raise AssertionError(f"no {verb!r} call was made")


@pytest.fixture
def driver(monkeypatch):
    d = DockerDriver()
    fake = _FakeDocker()
    monkeypatch.setattr(d, "_run", fake)
    monkeypatch.setattr(d, "_plant_canaries", lambda spec, masks: {})
    monkeypatch.setattr(d, "_plant_witness", lambda spec: None)
    d.fake = fake  # type: ignore[attr-defined]
    return d


def test_provision_starts_a_hold_and_not_the_agent(driver):
    """The one assertion the whole issue reduces to."""
    driver.provision(_spec())
    argv = driver.fake.argv_of("run")

    assert argv[-len(_HOLD_COMMAND):] == _HOLD_COMMAND
    # Not merely "the hold is last": the agent command must be absent entirely,
    # because a container that runs it is a container whose agent is already
    # working while attest() is still reading the boundary.
    assert "agent.py" not in argv, f"the agent is in the container's argv: {argv}"


def test_provision_refuses_a_sandbox_that_did_not_stay_up(monkeypatch):
    """A missing hold must not look like a broken boundary.

    Without this, an image that cannot run the hold exits instantly and every
    probe fails for a reason unrelated to containment, which is the exact
    confusion this change exists to remove.
    """
    d = DockerDriver()
    monkeypatch.setattr(d, "_run", _FakeDocker(running="false"))
    with pytest.raises(DriverError) as caught:
        d.provision(_spec())
    assert "did not stay up" in str(caught.value)
    assert _HOLD_COMMAND[0] in str(caught.value)


def test_release_runs_the_agent_in_the_attested_sandbox(driver, monkeypatch):
    sandbox = driver.provision(_spec())
    started: list[list[str]] = []

    class _Popen:
        def __init__(self, argv, **kwargs):
            started.append(argv)
            self.returncode = 0

    monkeypatch.setattr(subprocess, "Popen", _Popen)
    driver.release(sandbox)

    assert len(started) == 1
    argv = started[0]
    assert argv[1] == "exec"
    assert argv[-len(AGENT_COMMAND):] == AGENT_COMMAND
    # The working directory is the one part of the spec a bare exec does not
    # carry over in every runtime version, so it is passed rather than assumed.
    assert "--workdir" in argv


def test_wait_without_release_is_an_error_not_a_silent_zero(driver):
    """The ordering is enforced, not merely documented.

    A caller that forgot release() must not get an exit status, because any
    status it got would describe something other than the agent.
    """
    sandbox = driver.provision(_spec())
    with pytest.raises(DriverError) as caught:
        driver.wait(sandbox, timeout_seconds=1)
    assert "never released" in str(caught.value)


def test_the_agent_cannot_be_released_twice(driver, monkeypatch):
    sandbox = driver.provision(_spec())

    class _Popen:
        def __init__(self, argv, **kwargs):
            self.returncode = 0

    monkeypatch.setattr(subprocess, "Popen", _Popen)
    driver.release(sandbox)
    with pytest.raises(DriverError) as caught:
        driver.release(sandbox)
    assert "already been released" in str(caught.value)


def test_release_refuses_a_sandbox_this_driver_did_not_provision(driver):
    """The agent command lives with the driver that held it back.

    A Sandbox is just three strings, and `wl-enclave kill` reconstructs one
    from run.json in a different process. Such a driver has no command to run,
    and must say so rather than exec nothing.
    """
    with pytest.raises(DriverError) as caught:
        driver.release(Sandbox(id="dead1234", name="n", driver="docker"))
    assert "not provisioned by this driver" in str(caught.value)


def test_wait_returns_the_agents_status_not_the_containers(driver, monkeypatch):
    """The container outlives the agent now, so its status is not the run's."""
    sandbox = driver.provision(_spec())

    class _Popen:
        def __init__(self, argv, **kwargs):
            self.returncode = 3

        def communicate(self, timeout=None):
            return ("agent said this", None)

    monkeypatch.setattr(subprocess, "Popen", _Popen)
    driver.release(sandbox)

    assert driver.wait(sandbox, timeout_seconds=30) == 3
    # Read from the exec, not from `docker logs`, which now only ever shows the
    # hold. A pipe drains once, so wait() keeps what it read.
    assert "agent said this" in driver.logs(sandbox)


def test_a_timed_out_agent_is_left_running_so_its_output_survives(driver, monkeypatch):
    """wait() must not reap on timeout.

    The caller quarantines the sandbox, which ends the exec, and only then asks
    for the logs. Killing the process here would throw away whatever the agent
    had written before it was stopped, which is the part worth having.
    """
    sandbox = driver.provision(_spec())
    drained: list[str] = []

    class _Popen:
        returncode = None

        def __init__(self, argv, **kwargs):
            self.attempts = 0

        def communicate(self, timeout=None):
            self.attempts += 1
            if self.attempts == 1:
                raise subprocess.TimeoutExpired(cmd="exec", timeout=timeout)
            drained.append("drained")
            return ("wrote this before being stopped", None)

        def poll(self):
            return None

        def kill(self):
            pass

    monkeypatch.setattr(subprocess, "Popen", _Popen)
    driver.release(sandbox)

    assert driver.wait(sandbox, timeout_seconds=1) is None
    assert drained == [], "wait() drained the pipe instead of leaving it"
    assert "wrote this before being stopped" in driver.logs(sandbox)
    assert drained == ["drained"]
