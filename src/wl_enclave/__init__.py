"""Watchlight AI Enclave — a governed, isolated runtime for autonomous AI agents.

Two layers enforce on every run. The :mod:`~wl_enclave.drivers` runtime decides
where the agent may connect; Watchlight decides what authority it has. Both are
recorded in one hash-chained evidence bundle (:mod:`~wl_enclave.evidence`).
"""

__version__ = "0.2.1"
