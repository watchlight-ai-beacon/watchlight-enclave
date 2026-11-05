"""``enclave.yaml`` loading and validation."""

from __future__ import annotations

import pytest

from wl_enclave import config, evidence


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


# -- the loader and the guard must agree about what a rule is --------------

@pytest.mark.parametrize(
    "entry",
    ["*openai.com:443", "openai.*:443", "api.*.openai.com:443", "*:443", "*.:443"],
)
def test_a_wildcard_anywhere_but_a_leading_dot_is_refused(tmp_path, entry):
    """A containment bug, not a style preference.

    ``*openai.com`` once stripped to the dotless suffix ``openai.com``, and a
    suffix match then admitted ``evilopenai.com`` under a rule meant to name
    subdomains. Nothing downstream can recover the intent, so the shape is
    required at load.
    """
    body = MINIMAL + f'egress:\n  allow:\n    - "{entry}"\n'
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, body))
    assert any("wildcard" in p or "domain after" in p for p in exc.value.problems)


@pytest.mark.parametrize("port", ["0", "65536", "70000", "99999"])
def test_a_port_outside_the_valid_range_is_refused(tmp_path, port):
    """The loader used to accept what the guard refuses.

    The guard parses the port as a u16 and rejects zero, so it exited on
    startup while the run carried on — producing a bundle that read "attested,
    no attempts", which is the shape of a clean run.
    """
    body = MINIMAL + f'egress:\n  allow:\n    - "example.com:{port}"\n'
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, body))
    assert any("65535" in p for p in exc.value.problems)


@pytest.mark.parametrize(
    "entry",
    ["example.com:443", "*.openai.com:443", "a.b.c.example.com:1", "x.example.com:65535"],
)
def test_valid_rules_are_accepted(tmp_path, entry):
    body = MINIMAL + f'egress:\n  allow:\n    - "{entry}"\n'
    assert config.load(write(tmp_path, body)).egress_allow == [entry]


def test_the_loader_uses_the_guards_own_validator():
    """One validator, not two.

    Two copies drift, and the drift is the bug above: the loader accepting what
    the guard refuses.
    """
    from wl_enclave import config as config_module
    from wl_enclave.egress import entry_problem

    assert config_module.entry_problem is entry_problem


# -- the two validators must not disagree, in either direction ------------

@pytest.mark.parametrize(
    "entry,why",
    [
        ("example.com:²", "superscript two: isdigit() is True, int() raises"),
        ("example.com:٤٤٣", "Arabic-Indic digits: int() reads 443, Rust refuses"),
        ("evil.com\n:443", "trailing newline: `$` matches before it, fullmatch does not"),
    ],
)
def test_unicode_and_newline_ports_are_refused_without_crashing(tmp_path, entry, why):
    """Each of these was accepted, and the first one crashed `doctor`.

    `str.isdigit()` accepts any Unicode decimal. For U+00B2 `int()` then raises
    a ValueError that escaped as a traceback; for Arabic-Indic digits it
    succeeds and returns 443, while the guard's u16 parser refuses the string —
    so the loader passed a config that produced a guard exiting on startup.
    """
    body = MINIMAL + f'egress:\n  allow:\n    - "{entry}"\n'
    with pytest.raises(config.ConfigError) as exc:
        config.load(write(tmp_path, body))
    assert exc.value.problems, why


def test_the_allowlist_type_uses_the_same_validator_as_the_loader():
    """It had a regex of its own that was laxer than both the loader and guard.

    `Allowlist` is public and documents the schema, so a reader would
    reasonably take it as the authority on what a rule is.
    """
    from wl_enclave.egress import Allowlist, GuardError

    for bad in ["*openai.com:443", "host:0", "host:70000", "evil.com\n:443"]:
        with pytest.raises(GuardError):
            Allowlist([bad])
    assert Allowlist(["api.openai.com:443"]).entries == ["api.openai.com:443"]


def test_the_allowlist_type_has_no_second_matcher():
    """Enforcement is the guard's. A Python matcher would be a third semantics.

    The one it had disagreed with the guard: fnmatch's ``*`` matches the empty
    string, so ``.openai.com`` matched ``*.openai.com`` in Python and was
    refused in Rust.
    """
    from wl_enclave.egress import Allowlist

    assert not hasattr(Allowlist, "permits")


# -- the rules that governed a run are recorded by content ----------------

#: A complete, valid config. Written out in each test rather than shared by
#: reference so a test that needs to change one field cannot change another
#: test's expectations.
_VALID = """version: 1

agent:
  name: a
  command: ["true"]
  image: python:3.12-slim

policy: {policy}
"""


def _project(tmp_path, policy="./policies"):
    project = tmp_path / "proj"
    project.mkdir(exist_ok=True)
    (project / "enclave.yaml").write_text(_VALID.format(policy=policy))
    return project


def test_a_policy_path_outside_the_project_is_refused(tmp_path):
    """The bundle is mounted into the sandbox, so the path cannot be arbitrary.

    enclave.yaml lives in the workspace a run can write to, so without this an
    agent could point its successor's policy mount at any host directory.
    """
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "x.policy.json").write_text("{}")
    project = _project(tmp_path, policy=str(outside))
    with pytest.raises(config.ConfigError, match="outside the project directory"):
        config.load(project / "enclave.yaml")


def test_a_symlink_out_of_the_project_is_refused(tmp_path):
    """Checked after resolving, because a symlink defeats a textual check."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "x.policy.json").write_text("{}")
    project = _project(tmp_path)
    (project / "policies").symlink_to(outside, target_is_directory=True)
    with pytest.raises(config.ConfigError, match="outside the project directory"):
        config.load(project / "enclave.yaml")


def test_changing_a_policy_changes_the_governing_digest(tmp_path):
    """What makes a rewritten policy visible instead of silent.

    The workspace is writable by design, so a run can edit the rules its
    successor is held to. This cannot prevent that; it makes two runs under
    different rules impossible to mistake for two runs under the same rules.
    """
    project = _project(tmp_path)
    (project / "policies").mkdir(parents=True, exist_ok=True)
    (project / "policies" / "a.policy.json").write_text('{"allow": []}')

    before = config.load(project / "enclave.yaml").governing_digests()
    (project / "policies" / "a.policy.json").write_text('{"allow": ["*"]}')
    after = config.load(project / "enclave.yaml").governing_digests()

    assert before["combined"] != after["combined"]
    assert before["files"]["enclave.yaml"] == after["files"]["enclave.yaml"]
    assert before["files"]["policy/a.policy.json"] != after["files"]["policy/a.policy.json"]
    # Adding a rule file counts too: a permission can be granted in a new file.
    (project / "policies" / "b.policy.json").write_text("{}")
    assert config.load(project / "enclave.yaml").governing_digests()["combined"] != after["combined"]


def test_an_unreadable_rule_file_makes_the_bundle_incomplete(tmp_path):
    """A rule we cannot read is a rule the bundle cannot state."""
    bundle = tmp_path / "bundle"
    chain = evidence.ChainWriter(bundle)
    chain.append("run.open", {"purpose": "t"})
    chain.append("config.attested", {"digests": {
        "combined": "sha256:abc",
        "files": {"enclave.yaml": "sha256:def",
                  "policy/x.policy.json": "unreadable: Permission denied"},
    }})
    chain.append("run.close", {"exit_code": 0})
    chain.seal({"agent": "t"})

    result = evidence.verify(bundle)
    assert result.ok is True, "the chain is intact"
    assert result.verdict == "incomplete"
    assert any("cannot state what governed" in r for r in result.incomplete_reasons)
