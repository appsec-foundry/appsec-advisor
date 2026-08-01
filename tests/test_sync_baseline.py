"""Tests for scripts/sync_baseline.py.

Three properties carry the weight.

*Refusal.* The fetched text is vendored into the repository as security rules,
so a captive-portal page, a 404 body, or an unreachable host must stop the sync
rather than overwrite the copy that is already there.

*Atomicity of a version bump.* The bundled file, ``config.json`` and the README
beside the file all name the same baseline id. They move together or not at all;
a half-bumped repository would ship a copy the id gate rejects.

*Non-destructive edits.* ``config.json`` is edited in place, not re-serialised,
so unrelated fields keep their formatting.

The network is never touched: every case stubs the fetch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "sync_baseline.py"
sys.path.insert(0, str(SCRIPT.parent))

import baseline_check as bc  # noqa: E402
import install_baseline as ib  # noqa: E402
import sync_baseline as sb  # noqa: E402

PUBLISHED = "# Test Baseline\n\n`baseline-id: test-1.0`\n\n- Do the secure thing.\n"
VENDORED = "# Test Baseline\n\n`baseline-id: test-1.0`\n\n- Do the older thing.\n"

CONFIG = {
    "_comment": "kept verbatim",
    "baseline": {
        "enabled": True,
        "id": "test-1.0",
        "name": "Test Baseline",
        "url": "https://example.invalid/baseline.md",
        "fallback_file": "data/baselines/test.md",
        "install_filename": "secure-coding-baseline.md",
    },
    "pricing": {"input_per_1m": 3.00, "output_per_1m": 15.00},
}

README = (
    "# Bundled secure-coding baselines\n\n"
    "| File | Baseline id | Source |\n"
    "|---|---|---|\n"
    "| `test.md` | `test-1.0` | <https://example.invalid> |\n\n"
    "A build that adapts the rules must change the id (`test-1.0+acme`).\n"
)


@pytest.fixture
def plugin(tmp_path: Path) -> Path:
    root = tmp_path / "plugin"
    (root / "data" / "baselines").mkdir(parents=True)
    (root / "config.json").write_text(json.dumps(CONFIG, indent=2) + "\n", encoding="utf-8")
    (root / "data" / "baselines" / "test.md").write_text(VENDORED, encoding="utf-8")
    (root / "data" / "baselines" / "README.md").write_text(README, encoding="utf-8")
    return root


@pytest.fixture
def serves(monkeypatch):
    """Stub the published source. ``text=None`` makes the fetch fail."""

    def _serves(text: str | None):
        def fake_fetch(url: str) -> bytes:
            if text is None:
                raise ib.InstallError("connection refused")
            return text.encode("utf-8")

        monkeypatch.setattr(ib, "_fetch", fake_fetch)

    return _serves


def bundled(plugin: Path) -> str:
    return (plugin / "data" / "baselines" / "test.md").read_text(encoding="utf-8")


def configured_id(plugin: Path) -> str:
    return json.loads((plugin / "config.json").read_text(encoding="utf-8"))["baseline"]["id"]


# ---------- the ordinary case: same id, newer text -------------------------


def test_same_id_rewrites_the_bundled_copy(plugin: Path, serves):
    serves(PUBLISHED)
    steps = sb.sync(plugin)
    assert bundled(plugin) == PUBLISHED
    assert configured_id(plugin) == "test-1.0"
    assert any("wrote" in step for step in steps)


def test_identical_text_writes_nothing(plugin: Path, serves):
    (plugin / "data" / "baselines" / "test.md").write_text(PUBLISHED, encoding="utf-8")
    serves(PUBLISHED)
    steps = sb.sync(plugin)
    assert any("unchanged: the bundled copy" in step for step in steps)
    assert not any("wrote" in step for step in steps)


def test_dry_run_writes_nothing(plugin: Path, serves):
    serves(PUBLISHED)
    steps = sb.sync(plugin, dry_run=True)
    assert bundled(plugin) == VENDORED
    assert any("would write" in step for step in steps)


def test_derivative_id_counts_as_the_same_version(plugin: Path, serves):
    """``test-1.0+acme`` is the same rules adapted, not a version change."""
    derived = PUBLISHED.replace("test-1.0", "test-1.0+acme")
    serves(derived)
    sb.sync(plugin)
    assert bundled(plugin) == derived
    assert configured_id(plugin) == "test-1.0"


# ---------- refusal --------------------------------------------------------


def test_unreachable_source_does_not_touch_the_copy(plugin: Path, serves):
    serves(None)
    with pytest.raises(sb.SyncError):
        sb.sync(plugin)
    assert bundled(plugin) == VENDORED


def test_document_without_an_id_is_refused(plugin: Path, serves):
    serves("<html><body>Sign in to the guest network</body></html>")
    with pytest.raises(sb.SyncError):
        sb.sync(plugin)
    assert bundled(plugin) == VENDORED


def test_fallback_file_outside_the_plugin_is_refused(plugin: Path, serves):
    config = json.loads((plugin / "config.json").read_text(encoding="utf-8"))
    config["baseline"]["fallback_file"] = "../escaped.md"
    (plugin / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    serves(PUBLISHED)
    with pytest.raises(sb.SyncError):
        sb.sync(plugin)


def test_disabled_baseline_is_refused(plugin: Path, serves):
    config = json.loads((plugin / "config.json").read_text(encoding="utf-8"))
    config["baseline"]["enabled"] = False
    (plugin / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    serves(PUBLISHED)
    with pytest.raises(sb.SyncError):
        sb.sync(plugin)


# ---------- version change -------------------------------------------------


def test_new_id_stops_and_changes_nothing(plugin: Path, serves):
    serves(PUBLISHED.replace("test-1.0", "test-2.0"))
    with pytest.raises(sb.VersionChange) as excinfo:
        sb.sync(plugin)
    assert "test-2.0" in str(excinfo.value)
    assert bundled(plugin) == VENDORED
    assert configured_id(plugin) == "test-1.0"


def test_accepted_id_moves_file_config_and_readme_together(plugin: Path, serves):
    published = PUBLISHED.replace("test-1.0", "test-2.0")
    serves(published)
    sb.sync(plugin, accept_id="test-2.0")
    assert bundled(plugin) == published
    assert configured_id(plugin) == "test-2.0"
    readme = (plugin / "data" / "baselines" / "README.md").read_text(encoding="utf-8")
    assert "| `test.md` | `test-2.0` |" in readme
    # Prose that happens to mention the old id is left alone; only the row moves.
    assert "(`test-1.0+acme`)" in readme


def test_accepted_id_preserves_unrelated_config_formatting(plugin: Path, serves):
    serves(PUBLISHED.replace("test-1.0", "test-2.0"))
    sb.sync(plugin, accept_id="test-2.0")
    text = (plugin / "config.json").read_text(encoding="utf-8")
    assert '"_comment": "kept verbatim"' in text
    assert '"input_per_1m": 3.0' in text


def test_accepting_an_id_the_source_does_not_declare_is_refused(plugin: Path, serves):
    serves(PUBLISHED.replace("test-1.0", "test-2.0"))
    with pytest.raises(sb.SyncError):
        sb.sync(plugin, accept_id="test-3.0")
    assert bundled(plugin) == VENDORED
    assert configured_id(plugin) == "test-1.0"


def test_missing_readme_row_leaves_the_repository_unbumped(plugin: Path, serves):
    """Every edit is computed before anything is written."""
    (plugin / "data" / "baselines" / "README.md").write_text("# No table here\n", encoding="utf-8")
    serves(PUBLISHED.replace("test-1.0", "test-2.0"))
    with pytest.raises(sb.SyncError):
        sb.sync(plugin, accept_id="test-2.0")
    assert bundled(plugin) == VENDORED
    assert configured_id(plugin) == "test-1.0"


# ---------- CLI ------------------------------------------------------------


def test_main_reports_a_version_change_with_its_own_exit_code(plugin: Path, serves, capsys):
    serves(PUBLISHED.replace("test-1.0", "test-2.0"))
    assert sb.main(["--plugin-root", str(plugin)]) == 3
    assert "ACTION NEEDED" in capsys.readouterr().err


def test_main_succeeds_on_an_ordinary_refresh(plugin: Path, serves, capsys):
    serves(PUBLISHED)
    assert sb.main(["--plugin-root", str(plugin)]) == 0
    assert "source:" in capsys.readouterr().out


def test_main_reports_an_error_without_a_traceback(plugin: Path, serves, capsys):
    serves(None)
    assert sb.main(["--plugin-root", str(plugin)]) == 2
    assert capsys.readouterr().err.startswith("ERROR:")


# ---------- this repository ------------------------------------------------


def test_shipped_readme_row_matches_the_configured_id():
    """The row the bump edits has to exist, and has to agree with config.json.

    ``tests/test_baseline_check.py`` pins config.json against the bundled file;
    this pins the README that documents it, so all three cannot drift apart.
    """
    config = sb.load_release_config(REPO_ROOT)
    target = sb.bundled_target(config, REPO_ROOT)
    readme = target.parent / "README.md"
    assert readme.is_file(), "the bundled baseline needs a README naming its id"
    edited = sb.edit_readme_id(readme.read_text(encoding="utf-8"), target.name, config["id"], "probe-9.9")
    assert "`probe-9.9`" in edited
    assert bc.is_match(bc.find_ids(target.read_text(encoding="utf-8"))[0], config["id"])
