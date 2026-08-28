#!/usr/bin/env python3
"""Which versions a build carries, and whether they are still the current ones.

Three versions decide what a session actually does, and they move on separate
schedules: the plugin package a reader installed, the appsec-advisor core it was
built from, and the secure-coding baseline it names. A packaged organization
build makes the gap visible — its manifest version belongs to the organization,
while ``appsec_advisor_core_*`` records the upstream revision underneath.

Reading the local side is offline and always safe. Deciding whether those
versions are still current needs the published sources, so that half is opt-in:
``collect(check_updates=True)`` fetches the baseline document the build names and
the upstream manifest, and reports what it could not reach instead of guessing.

A branch build shares its core version string with every commit between two
upstream bumps, which is why the recorded commit and its date matter more there
than the version does.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _url_guard  # noqa: E402
import baseline_check as bc  # noqa: E402

HERE = Path(__file__).resolve().parent
PLUGIN_ROOT = HERE.parent

# A manifest, not a document: small enough that anything larger is a wrong
# answer, and bounded so a redirect cannot stream into memory.
MAX_FETCH_BYTES = 1_048_576
FETCH_TIMEOUT_SECONDS = 15

# The repository this plugin is published from. Used when a build carries no
# package surface — an unpackaged checkout — so the check still has a source.
DEFAULT_UPSTREAM_URL = "https://github.com/appsec-foundry/appsec-advisor"
MANIFEST_PATH = ".claude-plugin/plugin.json"

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str:
    """Return a single-line string, or empty when the value is unusable."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def _version_key(value: str) -> tuple | None:
    """Order ``0.6.0-beta.1`` below ``0.6.0``. None when nothing can order it.

    Numeric parts compare first, then release beats pre-release, then the
    pre-release identifiers compare the way SemVer orders them: numeric ones
    numerically, everything else as text.
    """
    match = _VERSION_RE.match(value.strip())
    if not match:
        return None
    numbers = tuple(int(part) for part in match.group(1).split("."))
    prerelease = match.group(2)
    if prerelease is None:
        return (numbers, 1, ())
    identifiers = tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in prerelease.split("."))
    return (numbers, 0, identifiers)


def compare(local: str, published: str) -> str:
    """``current``, ``behind``, ``ahead`` or ``unknown`` for two version strings.

    Equal strings are current even when neither parses — an exact match is an
    answer, and a build whose version this module cannot order still deserves
    one.
    """
    if not local or not published:
        return "unknown"
    if local == published:
        return "current"
    left, right = _version_key(local), _version_key(published)
    if left is None or right is None:
        return "unknown"
    if left == right:
        return "current"
    return "behind" if left < right else "ahead"


def published_manifest_url(upstream_url: str) -> str:
    """Raw URL of the upstream manifest, or empty for a host we cannot map.

    Only GitHub is mapped. Guessing a raw-file URL for an arbitrary forge would
    produce a request that fails, or worse, one that succeeds against something
    that is not the manifest.
    """
    url = _text(upstream_url)
    if not url:
        return ""
    match = re.match(r"^https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$", url)
    if not match:
        return ""
    owner, repository = match.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repository}/HEAD/{MANIFEST_PATH}"


def _fetch(url: str) -> bytes:
    """Fetch over https behind the URL guard. Raises ``FetchError`` on failure.

    The URL comes from plugin or organization configuration rather than from a
    scanned repository, so ``check_ip_safety=False``: an internal mirror is a
    legitimate source, and the allowlist is the control.
    """
    verdict = _url_guard.validate_target_url(url, check_ip_safety=False)
    if not verdict.ok:
        raise FetchError(f"blocked by URL guard: {verdict.reason}")
    request = urllib.request.Request(url, headers={"Accept": "text/markdown, application/json, text/plain, */*"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
            payload = response.read(MAX_FETCH_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise FetchError(str(exc)) from exc
    if len(payload) > MAX_FETCH_BYTES:
        raise FetchError(f"response larger than {MAX_FETCH_BYTES} bytes")
    return payload


class FetchError(Exception):
    """A published source could not be read; reported, never raised at a user."""


def _package_block(manifest: dict) -> dict:
    """Identity of the installed package itself.

    An organization build owns its own version number, and no one but that
    organization publishes it — so currency stays ``unknown`` here rather than
    being compared against the upstream release it has nothing to do with.
    """
    core_version = _text(manifest.get("appsec_advisor_core_version"))
    version = _text(manifest.get("version"))
    return {
        "name": _text(manifest.get("name")),
        "version": version,
        "organization_build": bool(core_version),
        "packaged_at": _text(manifest.get("appsec_advisor_packaged_at")),
        "state": "unknown" if core_version else "same-as-core",
    }


def _https_remote(remote: str) -> str:
    """An origin remote as a browsable https URL, or empty when it is neither."""
    match = re.match(r"^(?:git\+)?ssh://git@([^/]+)/(.+?)(?:\.git)?/?$", remote) or re.match(
        r"^git@([^:]+):(.+?)(?:\.git)?/?$", remote
    )
    if match:
        return f"https://{match.group(1)}/{match.group(2)}"
    return remote.removesuffix(".git") if remote.startswith("https://") else ""


def _git_source(root: Path) -> dict:
    """Branch, commit SHA, commit date, and origin from the git repo — best-effort."""
    import subprocess

    def _run(*cmd: str) -> str:
        try:
            return subprocess.run(list(cmd), capture_output=True, text=True, timeout=5, cwd=root).stdout.strip()
        except Exception:
            return ""

    ref = _run("git", "branch", "--show-current")
    log = _run("git", "log", "-1", "--format=%H %ci")
    parts = log.split(None, 1)
    return {
        "ref": ref,
        "commit": parts[0] if parts else "",
        "committed_at": parts[1] if len(parts) > 1 else "",
        "origin": _https_remote(_run("git", "remote", "get-url", "origin")),
    }


def _core_block(manifest: dict, surface: dict, *, check_updates: bool) -> dict:
    """The appsec-advisor revision underneath, and whether it is still current."""
    core_version = _text(manifest.get("appsec_advisor_core_version")) or _text(manifest.get("version"))
    ref = _text(manifest.get("appsec_advisor_core_ref"))
    commit = _text(manifest.get("appsec_advisor_core_commit"))
    committed_at = _text(manifest.get("appsec_advisor_core_committed_at"))
    origin = _text(surface.get("upstream_url"))
    if not ref and not commit:
        git = _git_source(PLUGIN_ROOT)
        ref = git.get("ref", "")
        commit = git.get("commit", "")
        committed_at = committed_at or git.get("committed_at", "")
        origin = origin or git.get("origin", "")
    block = {
        "version": core_version,
        "ref": ref,
        "commit": commit,
        "committed_at": committed_at,
        "dirty": bool(manifest.get("appsec_advisor_core_dirty")),
        "origin": origin.removesuffix(".git"),
        "published_version": "",
        "state": "not-checked",
        "note": "",
    }
    if not check_updates:
        return block

    url = published_manifest_url(_text(surface.get("upstream_url")) or DEFAULT_UPSTREAM_URL)
    if not url:
        block["state"] = "unknown"
        block["note"] = "the upstream repository is not a GitHub URL this check can map"
        return block
    try:
        published = json.loads(_fetch(url).decode("utf-8"))
    except (FetchError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        block["state"] = "unknown"
        block["note"] = str(exc)
        return block

    block["published_version"] = _text(published.get("version")) if isinstance(published, dict) else ""
    block["state"] = compare(core_version, block["published_version"])
    if not block["published_version"]:
        block["note"] = f"{url} carries no version"
    return block


def _baseline_block(config: dict, loaded: dict, *, check_updates: bool) -> dict:
    """The configured baseline id, what is loaded, and what upstream publishes.

    ``published`` answers a question ``verify-baseline`` cannot: that command
    reports whether the configured rules are loaded on this machine, not whether
    the build names the current version of them.
    """
    block = {
        "enabled": bool(config.get("enabled")),
        "configured_id": _text(config.get("id")),
        "name": _text(config.get("name")),
        "url": _text(config.get("url")),
        "loaded_status": _text(loaded.get("status")),
        "loaded_id": "",
        "loaded_scopes": bc.scope_text(loaded.get("scopes")),
        "published_id": "",
        "state": "not-checked",
        "note": "",
    }
    matches = loaded.get("matches") or loaded.get("newer") or loaded.get("other") or []
    if matches and isinstance(matches[0], dict):
        block["loaded_id"] = _text(matches[0].get("id"))

    if not block["enabled"]:
        block["state"] = "disabled"
        return block
    if not check_updates:
        return block

    url = _text(config.get("url"))
    if not url:
        block["state"] = "unknown"
        block["note"] = "this build names no baseline URL to compare against"
        return block
    try:
        document = _fetch(url).decode("utf-8", errors="replace")
    except FetchError as exc:
        block["state"] = "unknown"
        block["note"] = str(exc)
        return block

    ids = bc.find_ids(document)
    if not ids:
        block["state"] = "unknown"
        block["note"] = f"{url} declares no baseline id"
        return block
    block["published_id"] = ids[0]
    expected = block["configured_id"]
    if bc.is_match(block["published_id"], expected):
        block["state"] = "current"
    elif bc.is_newer(block["published_id"], expected):
        block["state"] = "outdated"
    else:
        block["state"] = "differs"
    return block


def collect(
    repo: Path | None = None,
    plugin_root: Path | None = None,
    *,
    check_updates: bool = False,
) -> dict:
    """Report package, core and baseline versions. Network only when asked to."""
    root = Path(plugin_root) if plugin_root else PLUGIN_ROOT
    manifest = _read_json(root / ".claude-plugin" / "plugin.json")
    surface = _read_json(root / ".claude-plugin" / "package-surface.json")
    config = bc.load_config(root)
    try:
        loaded = bc.check(repo=repo, config=config)
    except Exception:  # noqa: BLE001 — a status dump reports, it does not fail
        loaded = {}
    return {
        "checked_updates": check_updates,
        "package": _package_block(manifest),
        "core": _core_block(manifest, surface, check_updates=check_updates),
        "baseline": _baseline_block(config, loaded, check_updates=check_updates),
    }


def rows(data: dict) -> list[tuple[str, str]]:
    """The ``(label, value)`` lines a status dump prints for ``collect()``.

    Every line is unconditional. A reader diagnosing an installation on another
    machine needs to see that a build records no revision or no source URL just
    as much as they need the values — a row that disappears when its value is
    missing reads as "nothing to report" and hides exactly the builds worth
    asking about.
    """
    package, core, baseline = data["package"], data["core"], data["baseline"]
    out: list[tuple[str, str]] = []

    kind = "organization build" if package["organization_build"] else "upstream build"
    out.append(("Package", f"{package['name'] or '?'} {package['version'] or '?'}  ({kind})"))
    if package["packaged_at"]:
        out.append(("Packaged", package["packaged_at"]))

    core_parts = [core["version"] or "?"]
    revision = " @ ".join(part for part in (core["ref"], core["commit"][:12]) if part)
    core_parts.append(revision or "revision not recorded in this build")
    if core["committed_at"]:
        core_parts.append(core["committed_at"][:10])
    if core["dirty"]:
        core_parts.append("built from a modified tree")
    out.append(("Core", f"{' · '.join(core_parts)}{_state_suffix(core, 'published_version')}"))
    out.append(("Core source", core["origin"] or "not recorded in this build"))

    if baseline["enabled"]:
        configured = baseline["configured_id"] or "?"
        name = f" — {baseline['name']}" if baseline["name"] else ""
        out.append(("Baseline", f"{configured}{name}{_state_suffix(baseline, 'published_id')}"))
        out.append(("Baseline source", baseline["url"] or "no URL configured in this build"))
        out.append(("Baseline loaded", _loaded_text(baseline)))
    else:
        out.append(("Baseline", "not configured in this build"))
    return out


def _state_suffix(block: dict, published_key: str) -> str:
    state = block["state"]
    if state == "not-checked":
        return "  (pass --check-updates to compare)"
    if state == "current":
        return "  → current"
    if state in ("behind", "outdated"):
        return f"  → outdated, published {block[published_key]}"
    if state == "ahead":
        return f"  → ahead of published {block[published_key]}"
    if state == "differs":
        return f"  → differs from published {block[published_key]}"
    return f"  → not checked ({block['note'] or 'unknown'})"


def _loaded_text(baseline: dict) -> str:
    """What ``verify-baseline`` would say, in one line."""
    status = baseline["loaded_status"]
    if status == "missing":
        return "not loaded in Claude Code's instructions"
    if not status:
        return "unknown"
    where = baseline["loaded_scopes"] or status
    line = f"{baseline['loaded_id'] or status} ({where})"
    if status == "newer":
        return f"{line}, ahead of the configured id"
    if status == "other":
        return f"{line}, not the configured baseline"
    return line
