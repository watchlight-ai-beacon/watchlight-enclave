"""A deliberately misbehaving agent, governed by Watchlight inside a sandbox.

Five attempts, each one showing a different layer doing its job:

1. ``research`` — permitted. The tool body runs.
2. ``exfiltrate`` — refused by policy. The body never runs, and the decision is
   already on disk before this process could do anything about it.
3. an HTTPS request to the one host ``enclave.yaml`` allows — permitted by the
   egress guard, and recorded.
4. an HTTPS request somewhere else — refused by the guard, and recorded with the
   host, the port and the reason.
5. a raw socket to an arbitrary port — refused because there is no route at all.
   It speaks no CONNECT, so the guard cannot name it in a record: it is blocked
   but not described, which is the honest limit of this topology.

Run it through ``wl-enclave run``, not directly: the governed decisions are
written to the directory Enclave mounts, and that is what becomes evidence.
"""

import os
import pathlib
import socket
import urllib.error
import urllib.request

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


def fetch(url: str, note: str) -> None:
    """Make one HTTPS request through whatever proxy the environment names.

    ``urllib`` reads ``HTTPS_PROXY``, which Enclave sets to the guard. The
    proxy variables are a convenience, not the boundary: the sandbox is on an
    internal network, so there is nowhere else for a packet to go.

    The scheme is checked first, and that check is the interesting part of this
    function. ``urlopen`` also honours ``file://``, which reads a local path
    without touching the network at all — so the egress guard would never see
    it and no ``egress.attempt`` record would exist. An agent that builds a URL
    from model output can produce ``file:///etc/passwd`` as easily as an
    address. Copy this restriction along with the rest.
    """
    if not url.startswith("https://"):
        print(f"agent: refusing {url!r}: only https is fetched ({note})")
        return
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            print(f"agent: GET {url} -> {response.status} ({note})")
    except urllib.error.HTTPError as exc:
        # A 403 here is the guard refusing to open the tunnel, not the site.
        print(f"agent: GET {url} -> refused by the guard, HTTP {exc.code} ({note})")
    except OSError as exc:
        print(f"agent: GET {url} -> failed, {type(exc).__name__} ({note})")


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

    # 3. permitted by the guard, and recorded as an allow
    fetch("https://example.com/", "allowed by enclave.yaml")

    # 4. refused by the guard, and recorded as a deny with host, port and reason
    fetch("https://pastebin.com/", "not in enclave.yaml")

    # 5. no CONNECT, so no route and no named record
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=5)
        print("agent: UNCONTAINED — raw socket succeeded, which must not happen")
    except OSError as exc:
        print(f"agent: raw socket refused, no route — {type(exc).__name__}")


if __name__ == "__main__":
    main()
