"""Tests for scripts/baseline_release.py.

One property carries the weight: nothing a release serves reaches the caller
unless a configured key signed its manifest and the baseline matches that
manifest byte for byte. Every other case here is a way that property could fail
open — another key, a changed manifest, a file that differs from it, a manifest
replayed under another tag, or a release that is older than, or another baseline
than, the one configured.

The network is never touched: a fake GitHub serves every case. The signatures
are real, made with a throwaway key by the same ssh-keygen that verifies them.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import baseline_release as br  # noqa: E402

REPOSITORY = "example-org/baseline"
TAG = "aiscb-0.2.0"
TEXT = "# AI Secure Coding Baseline\n\n`baseline-id: aiscb-0.2.0`\n\n- Do the secure thing.\n"
_signed = itertools.count()


def make_key(directory: Path, name: str) -> tuple[Path, str]:
    """A throwaway ed25519 key and its allowed-signers line."""
    path = directory / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(path)],
        check=True,
        capture_output=True,
    )
    kind, key = path.with_name(name + ".pub").read_text(encoding="utf-8").split()[:2]
    return path, f"{br.SIGNER_PRINCIPAL} {kind} {key}"


def sign(key: Path, manifest: bytes, namespace: str = br.SIGNATURE_NAMESPACE) -> bytes:
    document = key.parent / f"manifest-{next(_signed)}.json"
    document.write_bytes(manifest)
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", namespace, str(document)],
        check=True,
        capture_output=True,
    )
    return document.with_name(document.name + ".sig").read_bytes()


def manifest_for(text: str, baseline_id: str = "aiscb-0.2.0", **extra: object) -> bytes:
    """The manifest the publisher signs, in its canonical form."""
    data = text.encode("utf-8")
    document = {
        "baseline_id": baseline_id,
        "files": {
            "scripts/install.py": {"sha256": "0" * 64, "size": 1},
            br.BASELINE_FILE: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
        },
        "schema": 1,
        **extra,
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


class FakeGitHub:
    """Serves one release through the two API endpoints the fetch reads."""

    def __init__(self, files: dict[str, bytes], tag: str = TAG, **release: object):
        self.files = files
        self.release = {"tag_name": tag, "draft": False, "prerelease": False, **release}

    def __call__(self, url: str) -> object:
        prefix = f"https://api.github.com/repos/{REPOSITORY}/"
        assert url.startswith(prefix), url
        rest = url[len(prefix) :]
        if rest == "releases/latest":
            return self.release
        path, _, query = rest.removeprefix("contents/").partition("?")
        assert query == f"ref={self.release['tag_name']}", "every file is read at the release tag"
        if path not in self.files:
            raise br.ReleaseError("HTTP Error 404: Not Found")
        return {"type": "file", "encoding": "base64", "content": base64.b64encode(self.files[path]).decode("ascii")}


@pytest.fixture
def key(tmp_path: Path) -> tuple[Path, str]:
    if shutil.which("ssh-keygen") is None:
        pytest.skip("needs OpenSSH ssh-keygen")
    return make_key(tmp_path, "release")


def published(signing_key: Path, text: str = TEXT, manifest: bytes | None = None, **release: object) -> FakeGitHub:
    """A release of ``text``, its manifest signed with ``signing_key``."""
    manifest = manifest_for(text) if manifest is None else manifest
    files = {
        br.MANIFEST_NAME: manifest,
        br.SIGNATURE_NAME: sign(signing_key, manifest),
        br.BASELINE_FILE: text.encode("utf-8"),
    }
    return FakeGitHub(files, **release)


def trusting(key: tuple[Path, str]) -> dict:
    return {"repository": REPOSITORY, "allowed_signers": [key[1]]}


# ---------- what passes ----------------------------------------------------


def test_a_signed_release_is_returned_with_the_id_it_declares(key):
    release = br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=published(key[0]))
    assert release.text == TEXT
    assert release.baseline_id == "aiscb-0.2.0"
    assert f"{REPOSITORY} release {TAG}" in release.origin
    assert "signature verified" in release.origin


def test_the_configured_version_itself_is_accepted(key):
    release = br.fetch_latest(trusting(key), "aiscb-0.2.0", fetch_json=published(key[0]))
    assert release.baseline_id == "aiscb-0.2.0"


def test_without_a_minimum_a_renamed_baseline_is_returned(key):
    """A sync decides a renamed id itself, through --accept-id."""
    renamed = TEXT.replace("aiscb-0.2.0", "rules-1.0")
    github = published(key[0], renamed, manifest_for(renamed, "rules-1.0"), tag="rules-1.0")
    assert br.fetch_latest(trusting(key), None, fetch_json=github).baseline_id == "rules-1.0"


# ---------- the signature --------------------------------------------------


def test_a_manifest_signed_by_another_key_is_refused(key, tmp_path: Path):
    intruder = make_key(tmp_path, "intruder")
    with pytest.raises(br.ReleaseError, match="not from a trusted release key"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=published(intruder[0]))


def test_a_signature_made_for_another_purpose_is_refused(key):
    """The namespace binds a signature to bundle manifests; the same key signing anything else does not pass."""
    github = published(key[0])
    github.files[br.SIGNATURE_NAME] = sign(key[0], github.files[br.MANIFEST_NAME], namespace="file")
    with pytest.raises(br.ReleaseError, match="not from a trusted release key"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=github)


def test_a_manifest_changed_after_signing_is_refused(key):
    github = published(key[0])
    github.files[br.MANIFEST_NAME] = manifest_for(TEXT + "- Injected.\n")
    with pytest.raises(br.ReleaseError, match="not from a trusted release key"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=github)


def test_without_ssh_keygen_nothing_verifies(key, monkeypatch):
    github = published(key[0])
    monkeypatch.setattr(br.shutil, "which", lambda name: None)
    with pytest.raises(br.ReleaseError, match="ssh-keygen"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=github)


def test_without_a_configured_key_nothing_is_fetched():
    def no_network(url: str) -> object:
        raise AssertionError(f"fetched {url} without a key to verify it")

    with pytest.raises(br.ReleaseError, match="no release signing key"):
        br.fetch_latest({"repository": REPOSITORY, "allowed_signers": []}, "aiscb-0.1.14", fetch_json=no_network)


# ---------- the manifest and the file it pins ------------------------------


def test_a_baseline_that_differs_from_its_manifest_is_refused(key):
    github = published(key[0])
    github.files[br.BASELINE_FILE] = TEXT.replace("secure", "sekure").encode("utf-8")
    with pytest.raises(br.ReleaseError, match="does not match its signed manifest"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=github)


def test_a_manifest_replayed_under_another_tag_is_refused(key):
    """An old signed manifest served as a newer release would pass for a release it is not."""
    with pytest.raises(br.ReleaseError, match="not release aiscb-0.3.0"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=published(key[0], tag="aiscb-0.3.0"))


def test_a_baseline_that_declares_another_id_than_its_manifest_is_refused(key):
    mislabelled = TEXT.replace("aiscb-0.2.0", "aiscb-0.1.9")
    github = published(key[0], mislabelled, manifest_for(mislabelled))
    with pytest.raises(br.ReleaseError, match="does not declare aiscb-0.2.0"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=github)


def test_an_unknown_manifest_field_is_refused(key):
    github = published(key[0], manifest=manifest_for(TEXT, note="a newer format"))
    with pytest.raises(br.ReleaseError, match="unexpected shape"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=github)


# ---------- which release qualifies ----------------------------------------


def test_a_prerelease_is_refused(key):
    with pytest.raises(br.ReleaseError, match="not a stable release"):
        br.fetch_latest(trusting(key), "aiscb-0.1.14", fetch_json=published(key[0], prerelease=True))


def test_a_release_older_than_the_configured_id_is_refused(key):
    with pytest.raises(br.ReleaseError, match="not aiscb-0.3 or a later version"):
        br.fetch_latest(trusting(key), "aiscb-0.3", fetch_json=published(key[0]))


def test_a_signed_release_of_another_baseline_is_refused(key):
    with pytest.raises(br.ReleaseError, match="not acme-sec-1.0"):
        br.fetch_latest(trusting(key), "acme-sec-1.0", fetch_json=published(key[0]))


def test_a_repository_that_is_not_owner_and_name_is_refused():
    with pytest.raises(br.ReleaseError, match="owner/name"):
        br.fetch_latest({"repository": "owner/..", "allowed_signers": ["k"]}, "aiscb-0.1.14")


def test_a_redirect_away_from_the_api_host_is_refused():
    request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/releases/latest")
    with pytest.raises(br.ReleaseError, match="redirect"):
        br._SameHostRedirect().redirect_request(request, None, 302, "Found", {}, "https://example.invalid/elsewhere")


# ---------- what this build ships ------------------------------------------


def test_the_shipped_baseline_comes_from_a_signed_release():
    """A branch or URL source trusts whoever can push to it; a signed release trusts only the key."""
    block = json.loads((REPO_ROOT / "config.json").read_text(encoding="utf-8"))["baseline"]
    assert not block.get("url") and not block.get("git")
    assert block["release"]["repository"] == "appsec-foundry/aiscb"
    assert block["release"]["allowed_signers"]
    assert all(line.split()[0] == br.SIGNER_PRINCIPAL for line in block["release"]["allowed_signers"])
