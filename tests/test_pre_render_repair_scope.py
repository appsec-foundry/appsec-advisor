"""Drift guard for the active fragment-fixer repair scope."""

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
FIXER_PROMPT = REPO_ROOT / "agents" / "appsec-fragment-fixer.md"


def _prompt() -> str:
    return FIXER_PROMPT.read_text(encoding="utf-8")


def test_repair_scope_is_a_binding_whitelist():
    prompt = _prompt()

    assert "re-author **only** the listed `fragments_to_rewrite`" in prompt
    assert "binding whitelist, not advice" in prompt
    assert "Refuse any target outside" in prompt


def test_repair_scope_preserves_the_deterministic_only_hard_ban():
    prompt = _prompt()

    assert "never edit deterministic fragments" in prompt
    for fragment in (
        "`system-overview.md`",
        "`architecture-diagrams.md`",
        "`assets.md`",
        "`attack-surface.md`",
        "`out-of-scope.md`",
    ):
        assert fragment in prompt
