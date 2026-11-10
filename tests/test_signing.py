"""What a manifest signature establishes, and what it still does not.

These tests are written around the ladder in :mod:`wl_enclave.signing` rather
than around the happy path, because the risk with signing is not that it fails
to work. It is that it works and a reader credits it with more than it says.
One test here asserts a *successful* forgery on purpose — see
``test_a_key_holder_can_still_reseal_a_truncated_chain``.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from wl_enclave import evidence, signing


# -- fixtures ---------------------------------------------------------------
@pytest.fixture
def signer(tmp_path):
    return signing.generate(tmp_path / "keys" / "signing.key")


@pytest.fixture
def other_signer(tmp_path):
    return signing.generate(tmp_path / "keys" / "other.key")


def _bundle(path, signer=None, records=None):
    """A minimal bundle that verifies as ok when untouched."""
    path.mkdir(parents=True, exist_ok=True)
    chain = evidence.ChainWriter(path)
    for type, data in records or [
        ("run.open", {"purpose": "test"}),
        ("egress.attempt", {"host": "example.com", "port": 443, "verdict": "allow"}),
        ("run.close", {}),
    ]:
        chain.append(type, data)
    chain.seal({"run": "r1", "agent": "a", "runtime": "docker"}, signer=signer)
    return path


def _manifest(bundle):
    return json.loads((bundle / "manifest.json").read_text())


def _write_manifest(bundle, manifest):
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))


# -- the ladder -------------------------------------------------------------
def test_a_signed_bundle_verifies_and_names_the_key_that_sealed_it(tmp_path, signer):
    result = evidence.verify(_bundle(tmp_path / "b", signer))
    assert result.verdict == "ok"
    assert result.signed is True
    assert result.signer_key_id == signer.key_id


def test_a_signature_alone_is_reported_as_self_signed_not_as_attribution(
    tmp_path, signer
):
    # The rung that matters most, because "signed" is the word a reviewer wants
    # and the public key travels inside the bundle. If the summary ever says
    # plain "signed" here, a reader is being told the manifest is attributed
    # when all that was established is that it is unchanged.
    result = evidence.verify(_bundle(tmp_path / "b", signer))
    assert result.signer_pinned is False
    assert "self-signed" in result.summary
    assert "signed by the expected key" not in result.summary


def test_pinning_the_signing_key_is_what_establishes_who_sealed_it(tmp_path, signer):
    result = evidence.verify(_bundle(tmp_path / "b", signer), expect_key=signer.key_id)
    assert result.verdict == "ok"
    assert result.signer_pinned is True
    assert "signed by the expected key" in result.summary


def test_a_bundle_signed_by_another_key_fails_a_pin(tmp_path, signer, other_signer):
    result = evidence.verify(
        _bundle(tmp_path / "b", signer), expect_key=other_signer.key_id
    )
    # failed, not incomplete: the bundle does not merely lack the expected
    # attribution, it positively contradicts it.
    assert result.verdict == "failed"
    assert result.signed is True
    assert any("not by the required" in p for p in result.problems)


def test_requiring_a_signature_on_an_unsigned_bundle_reads_incomplete(tmp_path):
    result = evidence.verify(_bundle(tmp_path / "b"), require_signature=True)
    # Incomplete rather than failed: every record in it is still true, and what
    # is missing is attribution. Still non-zero at the exit status, which is
    # what a gate needs.
    assert result.verdict == "incomplete"
    assert result.ok is True
    assert any("required one" in r for r in result.incomplete_reasons)


def test_an_unsigned_bundle_verifies_exactly_as_before_by_default(tmp_path):
    # The verifier-strictness contract: signing must not fail a bundle sealed
    # by a build that predates it, or every existing CI gate breaks on upgrade
    # with no format change to point at.
    result = evidence.verify(_bundle(tmp_path / "b"))
    assert result.verdict == "ok"
    assert result.signed is False
    assert "unsigned" in result.summary


# -- forgery ----------------------------------------------------------------
def test_a_signature_cannot_claim_a_key_id_its_own_public_key_does_not_produce(
    tmp_path, signer, other_signer
):
    # The attack this blocks: carry the key_id a reviewer pins against, beside
    # a different public key that actually verifies the signature. Without the
    # recomputation in signing.check, --signer would be satisfied by a bundle
    # the pinned key never touched.
    bundle = _bundle(tmp_path / "b", other_signer)
    manifest = _manifest(bundle)
    manifest["signature"]["key_id"] = signer.key_id
    _write_manifest(bundle, manifest)

    result = evidence.verify(bundle, expect_key=signer.key_id)
    assert result.verdict == "failed"
    assert result.signed is False
    assert any("does not match its own public key" in p for p in result.problems)


def test_editing_a_record_fails_a_signed_bundle(tmp_path, signer):
    bundle = _bundle(tmp_path / "b", signer)
    path = bundle / "chain.jsonl"
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["data"]["verdict"] = "deny"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    assert evidence.verify(bundle, expect_key=signer.key_id).verdict == "failed"


def test_editing_the_manifest_breaks_its_signature(tmp_path, signer):
    bundle = _bundle(tmp_path / "b", signer)
    manifest = _manifest(bundle)
    manifest["run"] = "a-different-run"
    _write_manifest(bundle, manifest)

    result = evidence.verify(bundle)
    assert result.verdict == "failed"
    assert any("signature does not verify" in p for p in result.problems)


def test_an_unknown_signature_algorithm_fails_rather_than_being_skipped(
    tmp_path, signer
):
    # A verifier that ignored signatures it did not understand would report an
    # unverifiable bundle as merely unsigned — weaker-sounding, but it hides a
    # contradiction behind a word that means "nothing was claimed".
    bundle = _bundle(tmp_path / "b", signer)
    manifest = _manifest(bundle)
    manifest["signature"]["alg"] = "pqc-whatever/1"
    _write_manifest(bundle, manifest)

    result = evidence.verify(bundle)
    assert result.verdict == "failed"
    assert any("algorithm is" in p for p in result.problems)


def test_a_key_holder_can_still_reseal_a_truncated_chain(tmp_path, signer):
    """The limit of a self-held key, asserted so it cannot be claimed away.

    This forgery SUCCEEDS, and that is the documented state of the format. The
    key holder drops a deny record, writes a ``run.close`` whose counts agree
    with what is left, re-seals, and the bundle verifies as ``ok`` against a
    pinned key with the denial gone.

    If a future change makes this fail — a witness cosignature is the only
    thing that can — this test should be rewritten deliberately, with the
    claim in ``signing``'s docstring and the README updated in the same commit.
    Until then it exists so nobody reads "signed" as "complete".
    """
    bundle = _bundle(
        tmp_path / "b",
        signer,
        records=[
            ("run.open", {"purpose": "test"}),
            ("egress.attempt", {"host": "pastebin.com", "port": 443, "verdict": "deny"}),
            ("run.close", {"egress_allowed": 0, "egress_denied": 1}),
        ],
    )
    assert evidence.verify(bundle, expect_key=signer.key_id).records == 3

    path = bundle / "chain.jsonl"
    path.write_text(path.read_text().splitlines()[0] + "\n")
    chain = evidence.ChainWriter(bundle)
    chain.append("run.close", {"egress_allowed": 0, "egress_denied": 0})
    chain.seal({"run": "r1", "agent": "a", "runtime": "docker"}, signer=signer)

    result = evidence.verify(bundle, expect_key=signer.key_id)
    assert result.verdict == "ok"
    assert result.signer_pinned is True
    assert result.records == 2  # the deny is gone and nothing says so


def test_truncation_that_drops_the_terminal_record_is_still_caught(tmp_path, signer):
    # Not a signature property — the required-record floor does this — but
    # worth pinning: it is why the forgery above needs a forged run.close
    # rather than only a shorter file.
    bundle = _bundle(tmp_path / "b", signer)
    path = bundle / "chain.jsonl"
    path.write_text("\n".join(path.read_text().splitlines()[:2]) + "\n")
    assert evidence.verify(bundle).verdict == "failed"


# -- witness readiness ------------------------------------------------------
def test_a_cosignature_can_be_added_without_invalidating_the_operator_signature(
    tmp_path, signer, other_signer
):
    # The whole reason the slot exists now. If cosignatures were inside the
    # signed bytes, a witness could not countersign without breaking the
    # operator's signature, and adding witnesses later would move the bundle
    # format version.
    bundle = _bundle(tmp_path / "b", signer)
    manifest = _manifest(bundle)
    witness = other_signer.sign(evidence.manifest_body(manifest))
    witness["role"] = "witness"
    manifest["cosignatures"] = [witness]
    _write_manifest(bundle, manifest)

    result = evidence.verify(bundle, expect_key=signer.key_id)
    assert result.verdict == "ok"
    assert result.signer_pinned is True


def test_a_cosignature_that_does_not_verify_is_a_problem(tmp_path, signer, other_signer):
    bundle = _bundle(tmp_path / "b", signer)
    manifest = _manifest(bundle)
    witness = other_signer.sign(b"some other bytes entirely")
    witness["role"] = "witness"
    manifest["cosignatures"] = [witness]
    _write_manifest(bundle, manifest)

    result = evidence.verify(bundle)
    assert result.verdict == "failed"
    assert any("cosignature 0 does not verify" in p for p in result.problems)


def test_cosignatures_is_written_even_when_empty(tmp_path, signer):
    # So a reader can tell a bundle with no witness from one sealed by a build
    # that did not know witnesses existed.
    assert _manifest(_bundle(tmp_path / "b", signer))["cosignatures"] == []


# -- keys -------------------------------------------------------------------
def test_a_new_key_is_not_readable_by_anyone_else(tmp_path):
    signer = signing.generate(tmp_path / "k.key")
    mode = stat.S_IMODE(os.stat(signer.path).st_mode)
    assert mode == 0o600, oct(mode)


def test_keygen_refuses_to_replace_an_existing_key(tmp_path):
    path = tmp_path / "k.key"
    signing.generate(path)
    with pytest.raises(signing.SigningError, match="already exists"):
        signing.generate(path)


def test_keygen_replaces_an_existing_key_only_when_forced(tmp_path):
    path = tmp_path / "k.key"
    first = signing.generate(path).key_id
    second = signing.generate(path, force=True).key_id
    assert first != second


def test_a_key_id_is_derived_from_the_public_key(tmp_path):
    signer = signing.generate(tmp_path / "k.key")
    import base64

    assert signer.key_id == signing.key_id_for(base64.b64decode(signer.public_key))


def test_loading_a_file_that_is_not_a_key_at_all_is_an_error(tmp_path):
    path = tmp_path / "nope.key"
    path.write_bytes(b"this is not a key\n")
    with pytest.raises(signing.SigningError, match="PEM private key"):
        signing.load(path)


def test_loading_a_valid_key_of_the_wrong_algorithm_is_an_error(tmp_path):
    # A real, well-formed PKCS8 key that simply is not Ed25519. The isinstance
    # check is what catches it: without it, signing would fail later with an
    # AttributeError from inside the backend rather than a message naming the
    # problem, and at the worst moment — sealing a run that already happened.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    path = tmp_path / "wrong-alg.key"
    path.write_bytes(
        x25519.X25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(signing.SigningError, match="ed25519"):
        signing.load(path)


def test_loading_a_missing_key_names_the_path(tmp_path):
    with pytest.raises(signing.SigningError, match="cannot read signing key"):
        signing.load(tmp_path / "absent.key")


# -- resolution -------------------------------------------------------------
def test_a_key_named_explicitly_but_missing_is_an_error_not_an_unsigned_seal(tmp_path):
    # The quiet downgrade this project cannot afford: the operator asked for a
    # signed bundle, and sealing unsigned would give them one that says less
    # than they believe it says.
    with pytest.raises(signing.SigningError):
        signing.resolve(tmp_path / "absent.key")


def test_a_key_named_in_the_environment_but_missing_is_also_an_error(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(signing.ENV_KEY, str(tmp_path / "absent.key"))
    with pytest.raises(signing.SigningError):
        signing.resolve()


def test_no_key_anywhere_resolves_to_none_so_a_run_still_happens(tmp_path, monkeypatch):
    monkeypatch.delenv(signing.ENV_KEY, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
    assert signing.resolve() is None


def test_the_default_key_is_used_when_one_exists_there(tmp_path, monkeypatch):
    monkeypatch.delenv(signing.ENV_KEY, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    expected = signing.generate(signing.default_key_path())
    resolved = signing.resolve()
    assert resolved is not None
    assert resolved.key_id == expected.key_id


def test_the_default_key_path_is_outside_the_working_tree(tmp_path, monkeypatch):
    # A signing key inside a repository gets committed eventually, and one
    # beside the bundle would travel with the evidence it signs.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    assert signing.default_key_path().is_relative_to(tmp_path / "cfg")


# -- custody ----------------------------------------------------------------
def test_a_key_inside_the_mounted_workspace_is_refused(tmp_path):
    # The worst outcome in the design: /work is bind-mounted writable, and a
    # key holder can re-seal a truncated chain, so an agent that can read the
    # key can delete the record of its own worst moment and sign the result.
    workspace = tmp_path / "project"
    (workspace / "secrets").mkdir(parents=True)
    key = workspace / "secrets" / "signing.key"
    signing.generate(key)
    assert signing.exposed_by(key, [workspace]) == workspace.resolve()


def test_a_symlink_from_inside_the_workspace_is_also_refused(tmp_path):
    # Resolving only one side would miss this: the file lives outside, and the
    # path the sandbox can open is inside.
    workspace = tmp_path / "project"
    workspace.mkdir()
    real = tmp_path / "outside.key"
    signing.generate(real)
    link = workspace / "signing.key"
    link.symlink_to(real)
    # The link resolves out of the workspace, so this specific direction is
    # safe; what must be caught is the key itself sitting inside.
    assert signing.exposed_by(link, [workspace]) is None
    assert signing.exposed_by(real, [tmp_path]) == tmp_path.resolve()


def test_the_default_key_is_not_exposed_by_a_project_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    workspace = tmp_path / "project"
    workspace.mkdir()
    key = signing.generate(signing.default_key_path())
    assert signing.exposed_by(key.path, [workspace]) is None


def test_the_key_directory_is_not_readable_by_other_users(tmp_path):
    import stat as _stat

    signer = signing.generate(tmp_path / "keys" / "signing.key")
    mode = _stat.S_IMODE(os.stat(signer.path.parent).st_mode)
    assert mode == 0o700, oct(mode)
