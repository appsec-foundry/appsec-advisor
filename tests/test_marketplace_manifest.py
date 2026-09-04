"""Guards for the marketplace catalog users add with `plugin marketplace add`.

Claude Code reads the catalog from the repository's default branch, which is
the development branch. What a user installs is decided solely by the entry's
`ref`, so a ref that drifts off the release branch ships unreleased code to
everyone without any other signal.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN = ROOT / ".claude-plugin" / "plugin.json"

# shields.io escapes a literal dash in a badge value as `--`, so the value ends
# at the first single dash, which separates it from the color.
VERSION_BADGE_RE = re.compile(r"img\.shields\.io/badge/version-(?P<value>(?:[^-]|--)+)-")


def _catalog() -> dict:
    return json.loads(MARKETPLACE.read_text(encoding="utf-8"))


def _entry() -> dict:
    plugins = _catalog()["plugins"]
    assert len(plugins) == 1, "a second entry needs a distinct plugin name and its own guard"
    return plugins[0]


def test_entry_name_matches_the_plugin_manifest():
    plugin = json.loads(PLUGIN.read_text(encoding="utf-8"))
    assert _entry()["name"] == plugin["name"]


def test_entry_installs_from_the_release_branch():
    source = _entry()["source"]
    assert source["source"] == "github"
    assert source["repo"] == "appsec-foundry/appsec-advisor"
    assert source["ref"] == "main"


def test_readme_documents_the_install_id():
    install_id = f"{_entry()['name']}@{_catalog()['name']}"
    assert install_id in (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_version_badge_matches_the_plugin_manifest():
    """The badge is the version a reader sees first, so it must not lag the manifest."""
    match = VERSION_BADGE_RE.search((ROOT / "README.md").read_text(encoding="utf-8"))
    assert match, "README has no shields.io version badge"
    badge_version = match.group("value").replace("--", "-")
    plugin = json.loads(PLUGIN.read_text(encoding="utf-8"))
    assert badge_version == plugin["version"], (
        f"README version badge says {badge_version}, plugin.json says {plugin['version']}"
    )
