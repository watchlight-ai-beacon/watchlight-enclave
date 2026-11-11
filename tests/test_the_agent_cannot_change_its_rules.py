"""The rules are readable from inside the sandbox and cannot be changed there.

``/policy`` was bound read-only from the start, and that was never the whole
story. The policy bundle lives inside the project root, which is bound writable
at ``/work`` so the agent can write code, and nothing masked it. Both paths
reach the same inodes, so the read-only bind covered a path while the files
behind it stayed writable through the other one: an agent could rewrite the
rules it was being judged by.

A second read-only bind at the workspace-relative location closes it in the
kernel rather than reporting it afterwards. Reads still work, and they have to:
the SDK inside the sandbox loads these files to make its decisions, so a
control that hid them would be describing a run that could not be governed at
all.
"""

import subprocess
from pathlib import Path

import pytest

from wl_enclave import attestation
from wl_enclave.cli import _seal_policy_in_workspace
from wl_enclave.drivers import Mount, Sandbox, SandboxSpec
from wl_enclave.drivers.docker import DockerDriver


ROOT = Path("/proj")


def test_the_policy_directory_is_sealed_where_the_workspace_exposes_it():
    mounts = _seal_policy_in_workspace(ROOT, ROOT / "policies")
    assert [m.target for m in mounts] == ["/work/policies"]
    assert mounts[0].read_only is True
    assert mounts[0].source == ROOT / "policies"


def test_a_policy_bundle_outside_the_workspace_needs_no_seal():
    """Nothing exposes it writably, so there is nothing to make read-only."""
    assert _seal_policy_in_workspace(ROOT, Path("/etc/wl-policies")) == []


def test_a_policy_bundle_that_is_the_workspace_is_not_sealed():
    """Sealing it would make the whole workspace read-only.

    An agent that cannot write anything cannot do the job, so the writable
    mount stands and the two readings in the chain are what report a change.
    """
    assert _seal_policy_in_workspace(ROOT, ROOT) == []


def _spec(mounts) -> SandboxSpec:
    return SandboxSpec(name="n", image="i", command=["true"], mounts=mounts)


def test_only_a_read_only_bind_inside_a_writable_one_counts_as_sealed():
    """/policy is read-only too, and it is not the interesting case.

    Nothing else reaches it, so read-only there is unremarkable. A read-only
    bind nested in a writable mount is a claim that a path the sandbox could
    otherwise write has been made unwritable, and only that claim is worth
    probing by effect.
    """
    sealed = DockerDriver()._sealed_paths(
        _spec(
            [
                Mount.bind(ROOT, "/work", read_only=False),
                Mount.bind(ROOT / "policies", "/work/policies", read_only=True),
                Mount.bind(ROOT / "policies", "/policy", read_only=True),
                Mount.mask("/work/runs"),
            ]
        )
    )
    assert sealed == ["/work/policies"]


class _Probes:
    """A docker CLI stand-in with scripted exit codes per probe verb."""

    def __init__(self, ls: int = 0, touch: int = 1) -> None:
        self.ls, self.touch = ls, touch
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str, timeout=None, check=True):
        self.calls.append(args)
        code = 0
        if args[0] == "exec":
            verb = args[2]
            code = {"ls": self.ls, "touch": self.touch}.get(verb, 0)
        return subprocess.CompletedProcess(list(args), code, stdout="", stderr="")

    def ran(self, verb: str) -> bool:
        return any(c[0] == "exec" and c[2] == verb for c in self.calls)


def _driver_with(probes, sealed=("/work/policies",)):
    d = DockerDriver()
    d._run = probes  # type: ignore[assignment]
    d._sealed["c1"] = list(sealed)
    return d, Sandbox(id="c1", name="n", driver="docker")


def test_readable_and_refusing_a_write_is_the_control_in_force():
    d, sandbox = _driver_with(_Probes(ls=0, touch=1))
    control = d._policy_control(sandbox)
    assert control["in_force"] is True
    assert control["verified_by"] == attestation.READBACK


def test_a_path_that_accepts_a_write_is_reported_and_the_probe_removed():
    """The failure this control exists to catch, and it must not litter."""
    probes = _Probes(ls=0, touch=0)
    d, sandbox = _driver_with(probes)
    control = d._policy_control(sandbox)
    assert control["in_force"] is False
    assert "accepted a write" in control["detail"]
    assert probes.ran("rm"), "a successful probe write was left behind"


def test_a_path_that_cannot_be_read_is_unconfirmed_not_sealed():
    """Unreadable is not sealed, it is unobserved.

    A run whose SDK cannot load its policy files is not governed at all, and
    reporting that as a control in force would be the strongest possible claim
    drawn from the weakest possible evidence.
    """
    probes = _Probes(ls=1)
    d, sandbox = _driver_with(probes)
    control = d._policy_control(sandbox)
    assert control["in_force"] is None
    assert not probes.ran("touch"), "a write was attempted on an unreadable path"


@pytest.mark.parametrize("code", [126, 127])
def test_a_probe_that_never_ran_says_nothing_about_the_path(code):
    """An image without `touch` must not attest a seal it never had."""
    d, sandbox = _driver_with(_Probes(ls=0, touch=code))
    assert d._policy_control(sandbox)["in_force"] is None


def test_no_sealed_path_is_unconfirmed_rather_than_in_force():
    d, sandbox = _driver_with(_Probes(), sealed=())
    assert d._policy_control(sandbox)["in_force"] is None


def test_the_seal_survives_the_other_controls_being_attested_first():
    """A regression, and the reason this test exists at all.

    The sealed-path state was first cleaned up inside the mask control, which
    attest() evaluates earlier in the same dict. By the time the policy probe
    ran there was nothing left to probe, and it reported "no path was sealed"
    for a run whose policy mount was in fact read-only — a control that silently
    understated itself while the end-to-end behaviour looked correct.
    """
    probes = _Probes(ls=0, touch=1)
    d, sandbox = _driver_with(probes)
    assert d._policy_control(sandbox)["in_force"] is True
    # Whatever else attest() does before reaching this control, the state it
    # needs is still there. Only teardown drops it.
    assert d._policy_control(sandbox)["in_force"] is True
    d._sealed.pop(sandbox.id, None)
    assert d._policy_control(sandbox)["in_force"] is None
