"""Signing a manifest, and what a signature here does and does not establish.

The hash chain catches edits: change a record and every hash after it
disagrees. It does nothing about truncation. Lop records off the end and what
remains is a shorter chain that verifies perfectly, because every hash still in
it is still correct. The manifest is what closes that hole — it pins the head
and the count — which is why the manifest is the thing worth signing, and the
only thing this module signs.

What a signature establishes is narrower than a reader tends to assume, so the
ladder is spelled out rather than left to inference:

**Unsigned.** The bundle proves its own internal consistency and nothing else.
It does not say who produced it.

**Signed by a key the verifier does not know.** Proves that whoever sealed the
bundle held an Ed25519 key, and that the manifest has not changed since. It
does *not* identify the signer: the public key travels inside the bundle, so
anyone can produce a bundle signed by a key of their own and it verifies. This
is the common case, and :func:`check` reports it as self-signed rather than as
attribution.

**Signed by a key the verifier pinned** — ``verify --signer`` — proves the
holder of that one key sealed this manifest. This is the first rung that says
anything about *who*, and it is the rung a CI gate should stand on.

No rung here defeats re-sealing. A key holder who truncates the chain can seal
and sign a fresh manifest over what is left, and the result verifies. Only a
cosignature from a witness the signer does not control closes that gap, which
is why every manifest carries a ``cosignatures`` list and why it is currently
empty: the slot is part of the format now so that adding a witness later does
not move the bundle format version. Claiming otherwise would be the one error
this format cannot afford, so :func:`check` never reports a self-signed bundle
as attributed.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Iterable, Optional

__all__ = [
    "ALG",
    "ROLE_OPERATOR",
    "ENV_KEY",
    "SigningError",
    "Signer",
    "key_id_for",
    "generate",
    "load",
    "default_key_path",
    "resolve",
    "exposed_by",
    "check",
]

#: The only algorithm this build writes or accepts. Named in each signature so
#: a future addition is a new value here rather than a reinterpretation of the
#: bytes already in circulation.
ALG = "ed25519"

#: The role an operator's own key signs under. A witness cosignature will carry
#: a different role, which is why the field exists before there is a second one.
ROLE_OPERATOR = "operator"

ENV_KEY = "WL_ENCLAVE_SIGNING_KEY"

_KEY_FILENAME = "signing.key"


class SigningError(Exception):
    """A key could not be created, read, or used."""


def _backend():
    """Import the crypto backend on use, not on import.

    ``cryptography`` is a declared dependency, so in a working install this
    always succeeds. It is imported lazily anyway so that verifying an
    *unsigned* bundle — the one thing a reviewer with a broken environment
    still needs to be able to do — does not depend on it loading.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - import guard
        raise SigningError(
            "signing needs the 'cryptography' package; install it with "
            "`pip install cryptography`"
        ) from exc
    return serialization, ed25519


def key_id_for(public_raw: bytes) -> str:
    """A key's identity: the digest of its public half.

    Derived rather than assigned, so two people naming the same key cannot
    disagree about what it is called, and a signature cannot claim an identity
    its own public key does not produce — :func:`check` recomputes this and
    rejects a mismatch.
    """
    return "sha256:" + hashlib.sha256(public_raw).hexdigest()


class Signer:
    """A loaded private key and the identity its signatures will carry."""

    def __init__(self, private_key, path: Optional[Path] = None) -> None:
        serialization, _ = _backend()
        self._private = private_key
        self.path = path
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_key = base64.b64encode(public_raw).decode("ascii")
        self.key_id = key_id_for(public_raw)

    def sign(self, payload: bytes) -> dict:
        """One signature entry, as it appears in a manifest.

        The public key travels with the signature so that verification needs
        nothing but the bundle — offline, with no key server and no network.
        That convenience is exactly why a bare signature is not attribution,
        and why the entry carries ``key_id`` for a verifier to pin against.
        """
        return {
            "alg": ALG,
            "role": ROLE_OPERATOR,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "sig": base64.b64encode(self._private.sign(payload)).decode("ascii"),
        }


def default_key_path() -> Path:
    """Where a key lives when nobody said otherwise.

    Outside the repository on purpose. A signing key inside a working tree gets
    committed eventually, and a key in the bundle's own directory would travel
    with the evidence it signs, which defeats the point of signing it.
    """
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "wl-enclave" / _KEY_FILENAME


def generate(path: Optional[Path] = None, force: bool = False) -> Signer:
    """Create a new Ed25519 key, refusing to replace one that exists.

    Overwriting is refused rather than confirmed because the old key is the
    only thing that can produce signatures matching bundles already sealed with
    it. Losing it does not invalidate those bundles — the public key is in each
    one — but it does end the operator's ability to be the same signer, and a
    silent overwrite would make that irreversible without a prompt.

    The key is written unencrypted at mode 0600, in a directory forced to 0700.
    A passphrase would have to be supplied on every seal, which rules out the
    unattended runs this is mostly for, so the protection here is filesystem
    permissions and nothing else: anyone who can read this file can sign, and a
    signer can re-seal a truncated chain.

    Keeping the private key out of the process entirely — a KMS or a hardware
    token — is the stronger arrangement and is **not implemented**. It is a
    small addition rather than a redesign, because :meth:`ChainWriter.seal`
    takes any object with a ``sign(payload) -> dict`` method; what does not
    exist is such an implementation or a way to select one.
    """
    serialization, ed25519 = _backend()
    path = Path(path) if path is not None else default_key_path()
    if path.exists() and not force:
        raise SigningError(
            f"{path} already exists; signatures made with the existing key "
            f"cannot be reproduced without it. Pass --force only if you are "
            f"certain it is not the key that sealed bundles you still need to "
            f"re-sign."
        )
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # 0700 on the directory as well as 0600 on the file. The file mode is what
    # stops another user reading the key; the directory mode stops them
    # learning it exists, and closes the window where anything else writing
    # here lands in a world-readable place. chmod as well as mkdir, because
    # mkdir's mode does nothing when the directory is already there.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        # A key kept in a directory we do not own — a mounted secret, say — is
        # a better arrangement than the default, not a worse one. Failing the
        # keygen because we could not tighten someone else's mount would push
        # the operator back to the default location.
        pass
    # 0600 before the bytes, not after: a key that is briefly world-readable on
    # a shared machine has already been exposed by the time chmod runs.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return Signer(private, path)


def load(path: Path) -> Signer:
    """Load a private key from a PEM file."""
    serialization, ed25519 = _backend()
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SigningError(f"cannot read signing key {path}: {exc}") from exc
    try:
        private = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise SigningError(f"{path} is not an unencrypted PEM private key: {exc}") from exc
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SigningError(
            f"{path} holds a {type(private).__name__}, but this build signs "
            f"with {ALG} only"
        )
    return Signer(private, path)


def resolve(explicit: Optional[Path] = None) -> Optional[Signer]:
    """Find the key to sign with, or ``None`` to seal unsigned.

    Three sources, most specific first: the path given on the command line, the
    ``WL_ENCLAVE_SIGNING_KEY`` environment variable, then the default location.

    The asymmetry is deliberate. A path given explicitly and missing is an
    error, because the operator asked for signing and did not get it, and
    sealing unsigned after being told to sign would be exactly the kind of
    quiet downgrade this project exists to make impossible. The default
    location merely being absent is not an error: it is the ordinary state of
    an install that has not run ``keygen``, and a run must not fail for it.
    """
    if explicit is not None:
        return load(Path(explicit))
    from_env = os.environ.get(ENV_KEY)
    if from_env:
        return load(Path(from_env))
    default = default_key_path()
    if default.exists():
        return load(default)
    return None


def exposed_by(key_path: Path, roots: "Iterable[Path]") -> Optional[Path]:
    """The directory that would hand this key to the sandbox, or ``None``.

    The workspace is bind-mounted into the sandbox writable, because the agent
    exists to edit it. A signing key kept anywhere inside it is therefore
    readable by the agent, and a key holder can re-seal a truncated chain — so
    an agent that reads this file can delete the record of its own worst
    moment and sign the result. That is the single worst outcome available in
    this design, and it is one ``--sign-key ./key.pem`` away.

    Both sides are resolved before comparing, so the check follows the file
    rather than the path used to name it, and a key that really sits inside the
    workspace is caught however it was reached. A symlink inside the workspace
    pointing at a key outside it is not caught, and does not need to be: the
    sandbox resolves that link in its own mount namespace, where the target
    path does not exist, so the bytes never become readable.

    Deliberately conservative. A key under ``runs/`` is in fact masked from the
    sandbox, and is still refused, because the exact shape of the mask is not
    something an operator should have to reason about to keep a private key
    private.
    """
    try:
        key = Path(key_path).resolve()
    except OSError:
        return None
    for root in roots:
        try:
            resolved = Path(root).resolve()
        except OSError:
            continue
        if key == resolved or resolved in key.parents:
            return resolved
    return None


def check(payload: bytes, entry: object) -> tuple[bool, str]:
    """Verify one signature entry against the bytes it should cover.

    Returns ``(ok, detail)``; ``detail`` names the reason on failure and the
    key on success, so a caller can report *which* key verified rather than
    only that one did.
    """
    if not isinstance(entry, dict):
        return False, "the signature is not an object"
    alg = entry.get("alg")
    if alg != ALG:
        # An unknown algorithm is a failure, not something to skip over. A
        # verifier that ignored signatures it did not understand would report
        # an unverified bundle as merely unsigned, which reads as weaker
        # evidence when it is actually a contradiction.
        return False, f"algorithm is {alg!r}, this verifier checks {ALG!r} only"
    try:
        public_raw = base64.b64decode(entry.get("public_key") or "", validate=True)
        sig = base64.b64decode(entry.get("sig") or "", validate=True)
    except (ValueError, TypeError) as exc:
        return False, f"public_key or sig is not valid base64: {exc}"
    if len(public_raw) != 32:
        return False, f"public key is {len(public_raw)} bytes, expected 32"
    claimed = entry.get("key_id")
    actual = key_id_for(public_raw)
    if claimed != actual:
        # The entry names an identity its own key does not produce. Caught
        # because key_id is what a reviewer pins with --signer: left unchecked,
        # a bundle could carry a trusted key_id beside an untrusted key and
        # satisfy the pin.
        return False, (
            f"key_id {str(claimed)[:23]}… does not match its own public key, "
            f"which is {actual[:23]}…"
        )
    try:
        _, ed25519 = _backend()
        ed25519.Ed25519PublicKey.from_public_bytes(public_raw).verify(sig, payload)
    except SigningError as exc:
        return False, str(exc)
    except Exception as exc:  # cryptography raises InvalidSignature
        return False, f"signature does not match the manifest ({type(exc).__name__})"
    return True, actual
