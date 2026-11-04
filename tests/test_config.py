"""``enclave.yaml`` loading and validation."""

from __future__ import annotations

import pytest

from wl_enclave import config


def write(tmp_path, body: str, policies: bool = True):
    if policies:
        (tmp_path / "policies").mkdir(exist_ok=True)
        (tmp_path / "policies" / "a.policy.json").write_text(
            '[{"name": "a", "code": "permit(principal, action, resource);"}]'
        )
    path = tmp_path / "enclave.yaml"
    path.write_text(body)
    return path


MINIMAL = """\
version: 1
agent:
  name: coder
  command: ["python", "agent.py"]
  image: python:3.12-slim
policy: ./policies
"""


def test_a_minimal_config_loads(tmp_path):
    cfg = config.load(write(tmp_path, MINIMAL))
    assert cfg.agent.name == "coder"
    assert cfg.agent.command == ["python", "agent.py"]
    assert cfg.runtime == "docker"
    assert cfg.egress_allow == []


def test_defaults_are_applied(tmp_path):
    cfg = config.load(write(tmp_path, MINIMAL))
    assert cfg.limits.memory == "2Gi"
    assert cfg.limits.timeout_seconds == 1800
    assert cfg.limits.memory_bytes == 2 * 1024**3


def test_a_missing_file_says_how_to_make_one(tmp_path):
    with pytest.raises(config.ConfigError) as exc:
        config.load(tmp_path / "enclave.yaml")
    assert "wl-enclave init" in exc.value.problems[0]


def test_every_problem_is_reported_not_just_the_first(tmp_path):
    """One pass must tell you everything to fix.

    Reporting one problem per run turns a bad config into a guessing game, and
    `doctor` exists precisely so that does not happen.
    """
    path = write(
        tmp_path,
        """\
version: 99
agent:
  command: []
runtime: nope
policy: ./missing
limits:
  memory: huge
  timeout: forever
  cpus: -1
""",
        policies=False,
    )
    with pytest.raises(config.ConfigError) as exc:
        config.load(path)
    joined = " ".join(exc.value.problems)
    for expected in ("version", "agent.name", "agent.command", "runtime", "policy",
                     "limits.memory", "limits.timeout", "limits.cpus"):
        assert expected in joined, f"{expected} was not reported; got {joined}"


@pytest.mark.parametrize(
    "image",
    ["--privileged", "--network=host", "-v", "img;rm -rf /", "img $(whoami)", "--rm"],
)
def test_an_image_that_would_be_read_as_a_flag_is_refused(tmp_path, image):
    """The argument-injection case.

    `docker run` parses flags up to the image, so an image of `--privileged`
    would be read as one and would undo the driver's isolation flags. Refused
    at load, before anything reaches a command line.
    """
    body = MINIMAL.replace("image: python:3.12-slim", f"image: {image!r}")
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, body))
    assert any("agent.image" in p for p in exc.value.problems)


@pytest.mark.parametrize(
    "image",
    ["python:3.12-slim", "ghcr.io/org/img:tag", "wl-enclave/coder:latest",
     "img@sha256:" + "a" * 64],
)
def test_ordinary_image_references_are_accepted(tmp_path, image):
    cfg = config.load(write(tmp_path, MINIMAL.replace("python:3.12-slim", image)))
    assert cfg.agent.image == image


def test_image_and_build_together_are_refused(tmp_path):
    body = MINIMAL.replace(
        "  image: python:3.12-slim",
        "  image: python:3.12-slim\n  build: ./Dockerfile",
    )
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, body))
    assert any("not both" in p for p in exc.value.problems)


def test_a_policy_directory_without_policy_files_is_refused(tmp_path):
    (tmp_path / "policies").mkdir()
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, MINIMAL, policies=False))
    assert any("policy.json" in p for p in exc.value.problems)


def test_a_malformed_egress_entry_is_refused(tmp_path):
    body = MINIMAL + "egress:\n  allow:\n    - no-port-here\n"
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, body))
    assert any("host:port" in p for p in exc.value.problems)


def test_egress_entries_are_kept_in_order(tmp_path):
    body = MINIMAL + "egress:\n  allow:\n    - b.example:443\n    - a.example:80\n"
    cfg = config.load(write(tmp_path, body))
    assert cfg.egress_allow == ["b.example:443", "a.example:80"]


def test_invalid_yaml_is_reported_as_such(tmp_path):
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, "version: 1\n  bad: [indent", policies=False))
    assert any("YAML" in p for p in exc.value.problems)
