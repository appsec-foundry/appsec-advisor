"""Tests for scripts/version_status.py.

Two properties carry the weight here.

*Honesty.* Every answer this module gives a reader is either measured or marked
as not measured. A source it cannot reach, a version string it cannot order, and
a forge it cannot map all end up as ``unknown`` with a reason — never as
"current", which is the one wrong answer that keeps someone on stale rules.

*Offline by default.* Reading the local versions must not touch the network, so
the fetch is stubbed everywhere and asserted to stay unused unless the caller
asked for an update check.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "version_status.py"
sys.path.insert(0, str(SCRIPT.parent))

import version_status as vs  # noqa: E402

BASELINE_DOCUMENT = "# Baseline\n\n`baseline-id: test-1.2`. When asked, answer.\n"


@pytest.fixture
def plugin(tmp_path: Path) -> Path:
    """A packaged organization build: org version outside, core recorded inside."""
    root = tmp_path / "plugin"
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps(
            {
                "name": "acme-appsec",
                "version": "1.2.0",
                "appsec_advisor_core_version": "0.6.0-beta.1",
                "appsec_advisor_core_ref": "dev",
                "appsec_advisor_core_commit": "9f2c1ab7c3d1" + "0" * 28,
                "appsec_advisor_core_committed_at": "2026-08-23T19:09:53+02:00",
                "appsec_advisor_packaged_at": "2026-08-24T07:30:00Z",
            }
        ),
        encoding="utf-8",
    )
    (root / ".claude-plugin" / "package-surface.json").write_text(
        json.dumps({"version": 1, "upstream_url": "https://github.com/appsec-foundry/appsec-advisor.git"}),
        encoding="utf-8",
    )
    (root / "config.json").write_text(
        json.dumps(
            {
                "baseline": {
                    "enabled": True,
                    "id": "test-1.0",
                    "name": "Test Baseline",
                    "url": "https://raw.githubusercontent.test/baseline.md",
                }
            }
        ),
        encoding="utf-8",
    )
    return root


def _served(monkeypatch, payloads: dict[str, bytes]) -> list[str]:
    """Stub the guarded fetch with canned responses; returns the URLs requested."""
    requested: list[str] = []

    def fake_fetch(url: str) -> bytes:
        requested.append(url)
        if url not in payloads:
            raise vs.FetchError("connection refused")
        return payloads[url]

    monkeypatch.setattr(vs, "_fetch", fake_fetch)
    return requested


def test_local_versions_are_read_without_touching_the_network(plugin: Path, monkeypatch) -> None:
    requested = _served(monkeypatch, {})
    data = vs.collect(repo=None, plugin_root=plugin)

    assert requested == []
    assert data["package"] == {
        "name": "acme-appsec",
        "version": "1.2.0",
        "organization_build": True,
        "packaged_at": "2026-08-24T07:30:00Z",
        "state": "unknown",
    }
    assert data["core"]["version"] == "0.6.0-beta.1"
    assert data["core"]["ref"] == "dev"
    assert data["core"]["committed_at"] == "2026-08-23T19:09:53+02:00"
    assert data["core"]["state"] == "not-checked"
    assert data["baseline"]["configured_id"] == "test-1.0"
    assert data["baseline"]["state"] == "not-checked"


def test_update_check_reports_outdated_baseline_and_current_core(plugin: Path, monkeypatch) -> None:
    manifest_url = vs.published_manifest_url("https://github.com/appsec-foundry/appsec-advisor.git")
    _served(
        monkeypatch,
        {
            "https://raw.githubusercontent.test/baseline.md": BASELINE_DOCUMENT.encode("utf-8"),
            manifest_url: json.dumps({"version": "0.6.0-beta.1"}).encode("utf-8"),
        },
    )
    data = vs.collect(repo=None, plugin_root=plugin, check_updates=True)

    assert data["baseline"]["published_id"] == "test-1.2"
    assert data["baseline"]["state"] == "outdated"
    assert data["core"]["state"] == "current"
    rendered = dict(vs.rows(data))
    assert "outdated, published test-1.2" in rendered["Baseline"]
    assert "current" in rendered["Core"]
    assert rendered["Package"] == "acme-appsec 1.2.0  (organization build)"


def test_newer_published_core_is_reported_as_behind(plugin: Path, monkeypatch) -> None:
    manifest_url = vs.published_manifest_url("https://github.com/appsec-foundry/appsec-advisor.git")
    _served(
        monkeypatch,
        {
            "https://raw.githubusercontent.test/baseline.md": BASELINE_DOCUMENT.encode("utf-8"),
            manifest_url: json.dumps({"version": "0.7.0"}).encode("utf-8"),
        },
    )
    data = vs.collect(repo=None, plugin_root=plugin, check_updates=True)

    assert data["core"]["state"] == "behind"
    assert data["core"]["published_version"] == "0.7.0"
    assert "outdated, published 0.7.0" in dict(vs.rows(data))["Core"]


def test_unreachable_sources_are_unknown_with_a_reason(plugin: Path, monkeypatch) -> None:
    _served(monkeypatch, {})
    data = vs.collect(repo=None, plugin_root=plugin, check_updates=True)

    assert data["core"]["state"] == "unknown"
    assert data["baseline"]["state"] == "unknown"
    assert "connection refused" in data["core"]["note"]
    assert "connection refused" in data["baseline"]["note"]
    assert "not checked" in dict(vs.rows(data))["Baseline"]


def test_document_without_a_marker_is_not_taken_as_current(plugin: Path, monkeypatch) -> None:
    manifest_url = vs.published_manifest_url("https://github.com/appsec-foundry/appsec-advisor.git")
    _served(
        monkeypatch,
        {
            "https://raw.githubusercontent.test/baseline.md": b"<html>login</html>",
            manifest_url: b"not json",
        },
    )
    data = vs.collect(repo=None, plugin_root=plugin, check_updates=True)

    assert data["baseline"]["state"] == "unknown"
    assert "declares no baseline id" in data["baseline"]["note"]
    assert data["core"]["state"] == "unknown"


def test_every_identity_line_is_printed_for_a_packaged_build(plugin: Path, monkeypatch) -> None:
    """A reader on another machine must see all of it without a second command."""
    _served(monkeypatch, {})
    rendered = dict(vs.rows(vs.collect(repo=None, plugin_root=plugin)))

    assert rendered["Package"] == "acme-appsec 1.2.0  (organization build)"
    assert rendered["Packaged"] == "2026-08-24T07:30:00Z"
    assert rendered["Core"].startswith("0.6.0-beta.1 · dev @ 9f2c1ab7c3d1 · 2026-08-23")
    assert rendered["Core source"] == "https://github.com/appsec-foundry/appsec-advisor"
    assert rendered["Baseline"].startswith("test-1.0 — Test Baseline")
    assert rendered["Baseline source"] == "https://raw.githubusercontent.test/baseline.md"
    assert "Baseline loaded" in rendered


def test_a_build_without_provenance_says_so_rather_than_dropping_the_line(tmp_path: Path, monkeypatch) -> None:
    """The silent case the packager used to produce: a version number and nothing else."""
    root = tmp_path / "plugin"
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "acme-appsec", "version": "1.2.0"}), encoding="utf-8"
    )
    (root / "config.json").write_text(json.dumps({"baseline": {"enabled": False}}), encoding="utf-8")
    _served(monkeypatch, {})
    monkeypatch.setattr(vs, "_git_source", lambda root: {"ref": "", "commit": "", "committed_at": "", "origin": ""})

    rendered = dict(vs.rows(vs.collect(repo=None, plugin_root=root)))

    assert rendered["Package"] == "acme-appsec 1.2.0  (upstream build)"
    assert "revision not recorded in this build" in rendered["Core"]
    assert rendered["Core source"] == "not recorded in this build"


def test_a_baseline_the_build_disabled_is_not_checked(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "plugin"
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"version": "0.6.0"}), encoding="utf-8")
    (root / "config.json").write_text(json.dumps({"baseline": {"enabled": False}}), encoding="utf-8")
    requested = _served(monkeypatch, {})

    data = vs.collect(repo=None, plugin_root=root, check_updates=True)

    assert data["baseline"]["state"] == "disabled"
    assert data["package"]["organization_build"] is False
    assert "not configured" in dict(vs.rows(data))["Baseline"]
    # The core is still checked; only the baseline document is skipped.
    assert requested == [vs.published_manifest_url(vs.DEFAULT_UPSTREAM_URL)]


@pytest.mark.parametrize(
    ("local", "published", "expected"),
    [
        ("0.6.0", "0.6.0", "current"),
        ("0.6.0-beta.1", "0.6.0", "behind"),
        ("0.6.0-beta.1", "0.6.0-beta.2", "behind"),
        ("0.7.0", "0.6.0", "ahead"),
        ("0.6.0+build.3", "0.6.0", "current"),
        ("nightly", "0.6.0", "unknown"),
        ("", "0.6.0", "unknown"),
    ],
)
def test_version_comparison(local: str, published: str, expected: str) -> None:
    assert vs.compare(local, published) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://github.com/appsec-foundry/appsec-advisor",
            "https://raw.githubusercontent.com/appsec-foundry/appsec-advisor/HEAD/.claude-plugin/plugin.json",
        ),
        (
            "https://github.com/appsec-foundry/appsec-advisor.git",
            "https://raw.githubusercontent.com/appsec-foundry/appsec-advisor/HEAD/.claude-plugin/plugin.json",
        ),
        ("https://gitlab.example.test/team/appsec-advisor.git", ""),
        ("git@github.com:appsec-foundry/appsec-advisor.git", ""),
        ("", ""),
    ],
)
def test_only_a_github_upstream_maps_to_a_manifest_url(url: str, expected: str) -> None:
    assert vs.published_manifest_url(url) == expected


def test_unmappable_upstream_is_reported_rather_than_guessed(plugin: Path, monkeypatch) -> None:
    surface = plugin / ".claude-plugin" / "package-surface.json"
    surface.write_text(
        json.dumps({"version": 1, "upstream_url": "https://gitlab.example.test/team/appsec-advisor.git"}),
        encoding="utf-8",
    )
    requested = _served(monkeypatch, {"https://raw.githubusercontent.test/baseline.md": BASELINE_DOCUMENT.encode()})

    data = vs.collect(repo=None, plugin_root=plugin, check_updates=True)

    assert data["core"]["state"] == "unknown"
    assert "not a GitHub URL" in data["core"]["note"]
    assert requested == ["https://raw.githubusercontent.test/baseline.md"]


def test_fetch_refuses_a_url_the_guard_rejects(monkeypatch) -> None:
    class Verdict:
        ok = False
        reason = "host not allowlisted"

    monkeypatch.setattr(vs._url_guard, "validate_target_url", lambda *a, **k: Verdict())
    with pytest.raises(vs.FetchError, match="URL guard"):
        vs._fetch("https://blocked.example.test/baseline.md")
