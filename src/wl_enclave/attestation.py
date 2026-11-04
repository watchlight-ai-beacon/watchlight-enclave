"""The vocabulary an attestation uses to name individual controls.

An attestation used to collapse a layer's enforcement into one boolean —
``route_exclusive`` for the guard, a handful of settings for the sandbox. That
is enough to say a layer held, and not enough to say *what* held. When a
reviewer asks why a bundle is weaker than they expected, the answer is always
about one specific control, and a boolean cannot carry it.

So each control is named, and each says two things: whether it was in force,
and how that was established. The second half is the point. A control read back
out of the runtime and a control we merely asked for are both "configured", and
in a bundle they are indistinguishable unless the record says which it was.

Three states, and they map onto the verdict :func:`wl_enclave.evidence.verify`
already produces rather than introducing a severity scale beside it:

``in_force=True``
    Established. Contributes nothing to the verdict; this is the normal case.

``in_force=False``
    The control was not in force. The layer did not hold, so the run is not
    attested — the caller raises this as a problem.

``in_force=None``
    Could not be determined. The control may well have held; we cannot say.
    This lands on ``incomplete``, which already means "everything here is true
    and some of what happened may be missing" — the same verdict a dropped
    record produces, for the same reason.

The names are constants because two layers emit them and one verifier reads
them. A control renamed on one side only would silently stop being checked,
which is the failure mode the closed record-type set exists to prevent for
record types.
"""

from __future__ import annotations

from typing import Optional

__all__ = [
    "READBACK",
    "REQUESTED",
    "RUNTIME_CONFIG",
    "TOPOLOGY",
    "NETWORK_UNROUTABLE",
    "SANDBOX_SINGLE_NETWORK",
    "GUARD_ATTACHED",
    "GUARD_HAS_EGRESS",
    "GUARD_LIVE",
    "ROOTFS_READ_ONLY",
    "CAPABILITIES_DROPPED",
    "NO_NEW_PRIVILEGES",
    "EVIDENCE_MASKED",
    "control",
    "merge",
    "unverified_controls",
    "failed_controls",
]

# -- how a control's state was established --------------------------------

#: Read out of the running system after the fact. The strongest thing we say.
READBACK = "runtime_readback"

#: Asked for at creation and not read back. Honest but weaker: a setting
#: applied and never confirmed is indistinguishable from one never applied.
REQUESTED = "requested_not_readback"

#: Read back from the runtime's record of the container's configuration. In
#: between the two above, and worth its own name: it is not our own argv echoed
#: back, so it catches a setting that never reached the daemon — but it is the
#: daemon's account of what was asked for, not the kernel's account of what is
#: in force. A mount destination, for instance, is normalised by the daemon
#: after this record is made.
RUNTIME_CONFIG = "runtime_config_readback"

#: True by construction rather than by inspection — there is no route to read
#: back because the topology never created one.
TOPOLOGY = "network_topology"

# -- control names, shared by every layer that attests ---------------------

NETWORK_UNROUTABLE = "network_unroutable"
SANDBOX_SINGLE_NETWORK = "sandbox_single_network"
GUARD_ATTACHED = "guard_attached"
GUARD_HAS_EGRESS = "guard_has_egress"
GUARD_LIVE = "guard_live_at_readback"
ROOTFS_READ_ONLY = "rootfs_read_only"
CAPABILITIES_DROPPED = "capabilities_dropped"
NO_NEW_PRIVILEGES = "no_new_privileges"
EVIDENCE_MASKED = "evidence_masked_from_sandbox"


def control(
    in_force: Optional[bool], verified_by: str, detail: str = ""
) -> dict:
    """One control's state, as it appears in an attestation record.

    ``detail`` is for the thing a reviewer would otherwise have to reconstruct
    — which extra network was attached, what the guard exited with. It is
    omitted when empty rather than carried as a null, so a record stays
    readable at a glance.
    """
    entry: dict = {"in_force": in_force, "verified_by": verified_by}
    if detail:
        entry["detail"] = detail
    return entry


#: How strong each state is. Lower is weaker, and weaker wins a merge.
_STRENGTH = {False: 0, None: 1, True: 2}


def merge(into: dict, new: dict) -> dict:
    """Fold one layer's controls into the running set, weakest claim winning.

    Order-independent on purpose. A run has more than one attesting moment —
    the topology is read when the sandbox is provisioned, the guard's fate is
    known only at the end — and taking the latest would let anything able to
    append a record overwrite a finding with a more flattering one. Taking the
    *weakest* cannot be abused in that direction: an attacker who can append
    records can only make the bundle describe a worse run than happened, which
    is the one direction that does not mislead a reviewer.

    It also gets the honest answer here for free. ``guard_live_at_readback``
    was genuinely in force when the topology was read and genuinely false by
    the end; the second fact is the one that bears on the evidence.
    """
    merged = dict(into)
    for name, entry in (new or {}).items():
        if not isinstance(entry, dict):
            continue
        held = merged.get(name)
        if held is None or _STRENGTH.get(entry.get("in_force"), 1) < _STRENGTH.get(
            held.get("in_force"), 1
        ):
            merged[name] = entry
    return merged


def unverified_controls(controls: dict) -> list[str]:
    """Names of controls whose state could not be determined.

    These are why a bundle reads ``incomplete`` rather than ``ok``: nothing in
    it is false, and something in it is unknown.
    """
    return sorted(
        name
        for name, entry in (controls or {}).items()
        if isinstance(entry, dict) and entry.get("in_force") is None
    )


def failed_controls(controls: dict) -> list[str]:
    """Names of controls established as *not* in force."""
    return sorted(
        name
        for name, entry in (controls or {}).items()
        if isinstance(entry, dict) and entry.get("in_force") is False
    )
