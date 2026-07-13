"""Drift guard for the Stage-2 pre-render repair scope instruction."""

from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
FINALIZATION_PROMPT = REPO_ROOT / "agents" / "phases" / "phase-group-finalization.md"


def _prompt() -> str:
    assert FINALIZATION_PROMPT.is_file(), f"expected phase-group prompt at {FINALIZATION_PROMPT}"
    return FINALIZATION_PROMPT.read_text(encoding="utf-8")


def test_repair_scope_is_a_binding_whitelist():
    prompt = _prompt()

    assert "**⚠⚠ HARD WHITELIST — `fragments_to_rewrite` is binding (not advisory):**" in prompt
    assert "**MUST edit only the path(s) listed in `actions[0].fragments_to_rewrite`.**" in prompt
    assert "The repair plan's `fragments_to_rewrite` is the **only** thing you may edit until compose succeeds." in prompt


def test_repair_scope_preserves_the_deterministic_only_hard_ban():
    prompt = _prompt()

    assert "**HARD BAN (P2 — A4):**" in prompt
    for fragment in (
        "`system-overview.md`",
        "`architecture-diagrams.md`",
        "`assets.md`",
        "`attack-surface.md`",
        "`out-of-scope.md`",
    ):
        assert fragment in prompt


def test_prompt_references_this_drift_guard():
    assert "`tests/test_pre_render_repair_scope.py` protects this binding-whitelist instruction against prompt drift." in _prompt()
