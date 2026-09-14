"""Fetch the latest signed release of a secure-coding baseline from GitHub.

Why a release and not a branch
------------------------------
A baseline read from a branch is whatever the last push left there, so it
trusts everyone who can push. The AI Secure Coding Baseline signs its releases
instead: ``bundle.json`` pins the size and SHA-256 of every file in a release,
and ``bundle.json.sig`` is an OpenSSH signature over that manifest by a release
key. Nothing here returns text until OpenSSH has verified the signature against
the keys in ``baseline.release.allowed_signers``, the manifest names the release
it was read from, and the baseline file matches the manifest byte for byte.

What the caller decides
-----------------------
Every failure raises ``ReleaseError``, and nothing is written here: the
installer falls back to the bundled copy, an update refuses, a sync stops.
``minimum`` is the configured id. A release of another baseline, or of an older
version, is refused, so a stale or foreign release never replaces the rules the
build names. A sync passes none, because there a new or renamed id is the
maintainer's decision, which ``--accept-id`` records.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _url_guard  # noqa: E402
import baseline_check as bc  # noqa: E402

API_HOST = "api.github.com"
# The REST API version the baseline's own installer pins for the same requests.
API_VERSION = "2026-03-10"
TIMEOUT_SECONDS = 15

# The release format of the AI Secure Coding Baseline. The namespace and the
# principal are part of what its release key signs, so they belong to the
# format rather than to configuration.
MANIFEST_NAME = "bundle.json"
SIGNATURE_NAME = "bundle.json.sig"
BASELINE_FILE = "secure-coding-baseline.md"
MANIFEST_SCHEMA = 1
SIGNATURE_NAMESPACE = "aiscb-bundle"
SIGNER_PRINCIPAL = "aiscb-release"
SIGNATURE_HEADER = b"-----BEGIN SSH SIGNATURE-----"
SSH_KEYGEN_TIMEOUT_SECONDS = 20

# What a response may make this process hold. The contents API wraps a file in
# base64 JSON, so its bound sits above the largest file it carries.
MAX_API_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 8 * 1024
MAX_BASELINE_BYTES = 256 * 1024

REPOSITORY_RE = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
_ID_RE = re.compile(r"(?P<name>[a-z][a-z0-9-]*)-(?P<version>\d+(?:\.\d+)*)")
_TAG_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


class ReleaseError(Exception):
    """The release could not be read or did not verify; reported without a traceback."""


@dataclass(frozen=True)
class Release:
    """A verified baseline: its text, the id it declares, and where it came from."""

    text: str
    baseline_id: str
    origin: str


def _parse_id(value: object) -> tuple[str, tuple[int, ...]] | None:
    """Split ``aiscb-0.1.14`` into ``("aiscb", (0, 1, 14))``; None for anything else.

    Stricter than ``baseline_check``: a released id carries no ``+`` derivative,
    because a derivative is by definition not what the publisher signed.
    """
    if not isinstance(value, str):
        return None
    match = _ID_RE.fullmatch(value)
    if match is None:
        return None
    return match.group("name"), tuple(int(part) for part in match.group("version").split("."))


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only while it stays on the API host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https" or target.hostname != API_HOST:
            raise ReleaseError(f"refused a redirect away from {API_HOST}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get_json(url: str) -> object:
    """GET one GitHub API document, behind the URL guard and bounded in size."""
    verdict = _url_guard.validate_target_url(url, check_ip_safety=False)
    if not verdict.ok:
        raise ReleaseError(f"blocked by URL guard: {verdict.reason}")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "appsec-advisor",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    opener = urllib.request.build_opener(_SameHostRedirect())
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_API_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ReleaseError(str(exc)) from exc
    if len(payload) > MAX_API_BYTES:
        raise ReleaseError(f"the release response is larger than {MAX_API_BYTES} bytes")
    try:
        return json.loads(payload.decode("utf-8"))
    except ValueError as exc:
        raise ReleaseError("the release response is not JSON") from exc


def _latest_tag(fetch_json: Callable[[str], object], repository: str) -> str:
    """The tag of the repository's latest stable release."""
    release = fetch_json(f"https://{API_HOST}/repos/{repository}/releases/latest")
    if not isinstance(release, dict):
        raise ReleaseError("the release lookup returned no release")
    if release.get("draft") or release.get("prerelease"):
        raise ReleaseError("the latest release is not a stable release")
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
        raise ReleaseError("the latest release has no usable tag")
    return tag


def _release_file(fetch_json: Callable[[str], object], repository: str, tag: str, path: str, limit: int) -> bytes:
    """One file of the release tree, read at the tag through the contents API."""
    query = urllib.parse.urlencode({"ref": tag})
    document = fetch_json(f"https://{API_HOST}/repos/{repository}/contents/{path}?{query}")
    if not (
        isinstance(document, dict)
        and document.get("type") == "file"
        and document.get("encoding") == "base64"
        and isinstance(document.get("content"), str)
    ):
        raise ReleaseError(f"release {tag} has no readable {path}")
    try:
        data = base64.b64decode("".join(document["content"].split()), validate=True)
    except ValueError as exc:
        raise ReleaseError(f"release {tag} serves {path} in an unreadable encoding") from exc
    if len(data) > limit:
        raise ReleaseError(f"release {tag} serves {path} larger than {limit} bytes")
    return data


def verify_signature(manifest: bytes, signature: bytes, allowed_signers: list[str]) -> None:
    """Have OpenSSH check the manifest signature against the configured release keys."""
    if not signature.startswith(SIGNATURE_HEADER) or len(signature) > MAX_SIGNATURE_BYTES:
        raise ReleaseError("the manifest signature is not an OpenSSH signature")
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        raise ReleaseError("ssh-keygen (OpenSSH) is required to verify the release signature")
    with tempfile.TemporaryDirectory(prefix="appsec-baseline-verify-") as tmp:
        signers = Path(tmp) / "allowed_signers"
        signed = Path(tmp) / SIGNATURE_NAME
        signers.write_text("".join(f"{line}\n" for line in allowed_signers), encoding="utf-8")
        signed.write_bytes(signature)
        try:
            done = subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "verify",
                    "-f",
                    str(signers),
                    "-I",
                    SIGNER_PRINCIPAL,
                    "-n",
                    SIGNATURE_NAMESPACE,
                    "-s",
                    str(signed),
                ],
                input=manifest,
                capture_output=True,
                timeout=SSH_KEYGEN_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseError(f"ssh-keygen could not verify the signature: {exc}") from exc
    if done.returncode != 0:
        raise ReleaseError("the manifest signature is not from a trusted release key")


def _pinned_baseline(manifest: bytes) -> tuple[object, int, str]:
    """Return ``(baseline_id, size, sha256)`` of the baseline file the manifest pins.

    Only the schema-1 shape is read, and an unknown top-level field is a refusal:
    it would be a format this reader does not understand. The other files in the
    bundle are the publisher's installer, which this plugin never runs.
    """
    try:
        document = json.loads(manifest.decode("utf-8"))
    except ValueError as exc:
        raise ReleaseError("the manifest is not JSON") from exc
    if not isinstance(document, dict) or set(document) != {"schema", "baseline_id", "files"}:
        raise ReleaseError("the manifest has an unexpected shape")
    if document["schema"] != MANIFEST_SCHEMA:
        raise ReleaseError(f"manifest schema {document['schema']!r} is not supported")
    files = document["files"]
    entry = files.get(BASELINE_FILE) if isinstance(files, dict) else None
    if not isinstance(entry, dict) or set(entry) != {"size", "sha256"}:
        raise ReleaseError(f"the manifest pins no {BASELINE_FILE}")
    size, digest = entry["size"], entry["sha256"]
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_BASELINE_BYTES:
        raise ReleaseError(f"the manifest pins no valid size for {BASELINE_FILE}")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ReleaseError(f"the manifest pins no valid digest for {BASELINE_FILE}")
    return document["baseline_id"], size, digest


def fetch_latest(
    release: dict,
    minimum: str | None,
    *,
    fetch_json: Callable[[str], object] = _get_json,
    verify: Callable[[bytes, bytes, list[str]], None] = verify_signature,
) -> Release:
    """Return the latest release of ``release['repository']``, verified end to end.

    ``minimum`` is the configured baseline id: the release has to be that
    baseline at that version or a later one. ``None`` accepts any signed release.
    """
    repository = str(release.get("repository") or "").strip()
    if not REPOSITORY_RE.fullmatch(repository) or repository.split("/")[1] in (".", ".."):
        raise ReleaseError(f"'{repository}' is not an owner/name GitHub repository")
    signers = release.get("allowed_signers")
    if not (
        isinstance(signers, list)
        and signers
        and all(isinstance(line, str) and line.strip() and not set(line) & {"\n", "\r"} for line in signers)
    ):
        raise ReleaseError("no release signing key is configured")
    floor = _parse_id(minimum) if minimum is not None else None
    if minimum is not None and floor is None:
        raise ReleaseError(f"the configured id {minimum} names no released version")

    tag = _latest_tag(fetch_json, repository)
    manifest = _release_file(fetch_json, repository, tag, MANIFEST_NAME, MAX_MANIFEST_BYTES)
    signature = _release_file(fetch_json, repository, tag, SIGNATURE_NAME, MAX_SIGNATURE_BYTES)
    verify(manifest, signature, signers)

    baseline_id, size, digest = _pinned_baseline(manifest)
    parsed = _parse_id(baseline_id)
    if parsed is None:
        raise ReleaseError(f"the manifest names no released baseline: {baseline_id!r}")
    name, version = parsed
    released = str(baseline_id)[len(name) + 1 :]
    if tag not in (released, f"v{released}", baseline_id):
        raise ReleaseError(f"the signed manifest describes {baseline_id}, not release {tag}")
    if floor is not None and (name != floor[0] or version < floor[1]):
        raise ReleaseError(f"the latest release is {baseline_id}, not {minimum} or a later version of it")

    content = _release_file(fetch_json, repository, tag, BASELINE_FILE, size)
    if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
        raise ReleaseError(f"release {tag} serves a {BASELINE_FILE} that does not match its signed manifest")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError(f"release {tag} serves a {BASELINE_FILE} that is not UTF-8") from exc
    if baseline_id not in bc.find_ids(text):
        raise ReleaseError(f"release {tag} serves a baseline that does not declare {baseline_id}")
    return Release(text, str(baseline_id), f"{repository} release {tag}, signature verified")
