"""A deliberately misbehaving agent, governed by Watchlight inside a sandbox.

Three attempts, each one showing a different layer doing its job:

1. ``research`` — permitted. The tool body runs.
2. ``exfiltrate`` — refused by policy. The body never runs, and the decision is
   already on disk before this process could do anything about it.
3. a direct network connection — refused by the sandbox, which Watchlight never
   sees, because the attempt never leaves the box.

Run it through ``wl-enclave run``, not directly: the governed decisions are
written to the directory Enclave mounts, and that is what becomes evidence.
"""

import os
import pathlib
import socket

from watchlight import Denied, configure_default, govern

AGENT = os.environ.get("WL_ENCLAVE_AGENT", "coder")
PURPOSE = os.environ.get("WL_ENCLAVE_PURPOSE", "")
POLICY_DIR = pathlib.Path(os.environ.get("WL_ENCLAVE_POLICY", "/policy"))


@govern.tool(intent="research")
def read_ticket(ticket: str) -> str:
    """In scope: the agent is here to read a ticket."""
    return f"ticket {ticket}: the login button is misaligned on mobile"


@govern.tool(intent="exfiltrate")
def post_to_pastebin(payload: str) -> str:
    """Out of scope. The body must never run."""
    return f"uploaded {len(payload)} bytes"


def main() -> None:
    configure_default(agent=AGENT)

    # The same policy bundle Enclave compiled, loaded from the read-only mount.
    for bundle in sorted(POLICY_DIR.glob("*.policy.json")):
        govern.load(bundle)
        print(f"agent: loaded policy {bundle.name}")

    print(f"agent: {AGENT} starting" + (f" — {PURPOSE}" if PURPOSE else ""))

    # 1. permitted
    print("agent:", read_ticket("PR-412"))

    # 2. refused by policy, before the body runs
    try:
        post_to_pastebin("the whole customer table")
        print("agent: UNGOVERNED — the exfiltrate body ran, which must not happen")
    except Denied as exc:
        print(f"agent: denied as expected — {exc}")

    # 3. refused by the sandbox; Watchlight never sees this
    try:
        socket.create_connection(("example.com", 443), timeout=5)
        print("agent: UNCONTAINED — egress succeeded, which must not happen")
    except OSError as exc:
        print(f"agent: egress refused by the sandbox — {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
