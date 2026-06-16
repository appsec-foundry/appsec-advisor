"""Tests for scripts/budget_watchdog.py.

Watchdog is called from agent_logger.handle_post_tool_use once per tool
call. These tests exercise the public API directly with a synthetic
agents/ directory so we can pin maxTurns per test.
"""

import json
import sys
from pathlib import Path

import pytest

PLUGIN_SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))

import budget_watchdog as bw  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_cache():
    """Reset the maxTurns cache between tests — different fixtures use
    different agent files and the module-level cache would leak."""
    bw._MAX_TURNS_CACHE.clear()
    yield
    bw._MAX_TURNS_CACHE.clear()


def _make_plugin_root(tmp_path: Path, agent_name: str, max_turns: int) -> Path:
    """Create a minimal $CLAUDE_PLUGIN_ROOT layout with one agent file."""
    root = tmp_path / "plugin"
    (root / "agents").mkdir(parents=True)
    (root / "agents" / f"{agent_name}.md").write_text(
        f"---\nname: {agent_name}\nmaxTurns: {max_turns}\n---\nbody\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fixture returning (output_dir, plugin_root) with one agent file
    `appsec-test-agent` defined at maxTurns=10."""
    root = _make_plugin_root(tmp_path, "appsec-test-agent", 10)
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    return output_dir, root


# ---------------------------------------------------------------------------
# get_max_turns
# ---------------------------------------------------------------------------


def test_get_max_turns_reads_frontmatter(env):
    assert bw.get_max_turns("appsec-test-agent") == 10


def test_get_max_turns_caches_result(env):
    bw.get_max_turns("appsec-test-agent")
    # Mutate file to a different value — should not change cached lookup
    root = env[1]
    (root / "agents" / "appsec-test-agent.md").write_text(
        "---\nname: appsec-test-agent\nmaxTurns: 999\n---\n", encoding="utf-8"
    )
    assert bw.get_max_turns("appsec-test-agent") == 10


def test_get_max_turns_tries_appsec_prefix(env):
    """Caller may pass bare `test-agent`; resolver tries `appsec-test-agent`."""
    assert bw.get_max_turns("test-agent") == 10


def test_get_max_turns_falls_back_when_file_missing(monkeypatch, tmp_path):
    """No matching agent file → DEFAULT_MAX_TURNS, never raises."""
    root = tmp_path / "plugin"
    (root / "agents").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    assert bw.get_max_turns("does-not-exist") == bw.DEFAULT_MAX_TURNS


def test_get_max_turns_falls_back_when_plugin_root_unset(monkeypatch):
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    assert bw.get_max_turns("anything") == bw.DEFAULT_MAX_TURNS


def test_get_max_turns_falls_back_when_no_frontmatter_field(env, tmp_path):
    """Agent file exists but has no `maxTurns:` line — fall back, don't crash."""
    root = env[1]
    (root / "agents" / "appsec-no-turns.md").write_text(
        "---\nname: appsec-no-turns\nmodel: sonnet\n---\n", encoding="utf-8"
    )
    assert bw.get_max_turns("appsec-no-turns") == bw.DEFAULT_MAX_TURNS


# ---------------------------------------------------------------------------
# tally_and_check — threshold crossings
# ---------------------------------------------------------------------------


def test_no_crossing_below_warn_threshold(env):
    output_dir, _ = env
    for _ in range(7):  # 7/10 = 70%, below 75% warn
        result = bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
        assert result is None


def test_warn_fires_at_75_percent(env):
    output_dir, _ = env
    results = [
        bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
        for _ in range(8)  # 8/10 = 80% — crosses 75%
    ]
    # Only the 8th call crosses the threshold; first 7 return None
    assert results[:7] == [None] * 7
    crossing = results[7]
    assert crossing is not None
    assert crossing["event"] == "BUDGET_WARN"
    assert crossing["turns"] == 8
    assert crossing["max"] == 10


def test_warn_fires_at_most_once(env):
    output_dir, _ = env
    seen_warn = 0
    for _ in range(9):  # 9 calls — 75% crossed at 8, 90% crossed at 9
        r = bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
        if r and r["event"] == "BUDGET_WARN":
            seen_warn += 1
    assert seen_warn == 1


def test_critical_fires_at_90_percent(env):
    output_dir, _ = env
    crossings = []
    for _ in range(9):
        r = bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
        if r:
            crossings.append(r)
    events = [c["event"] for c in crossings]
    assert "BUDGET_WARN" in events
    assert "BUDGET_CRITICAL" in events


def test_critical_writes_flag_file(env):
    output_dir, _ = env
    for _ in range(9):
        bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
    flag = output_dir / bw.CRITICAL_FLAG_FILENAME
    assert flag.is_file(), "BUDGET_CRITICAL must write the wrap-up flag file"
    data = json.loads(flag.read_text())
    assert isinstance(data, list)
    assert any(e["sid"] == "sid12345" for e in data)


def test_warn_writes_flag_file(env):
    output_dir, _ = env
    for _ in range(8):
        bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
    assert (output_dir / bw.WARN_FLAG_FILENAME).is_file()


def test_max_turns_fires_at_100_percent(env):
    output_dir, _ = env
    last = None
    for _ in range(10):
        last = bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
    assert last is not None
    assert last["event"] == "MAX_TURNS"


def test_max_turns_implies_warn_and_critical_already_marked(env):
    """If the agent somehow skipped intermediate thresholds (e.g. state file
    reset), the watchdog should still emit MAX_TURNS exactly once."""
    output_dir, _ = env
    # Force the state to skip all earlier thresholds.
    state = {
        "sid12345": {
            "agent": "appsec-test-agent",
            "turns": 9,
            "max_turns": 10,
            "warn_emitted": True,
            "critical_emitted": True,
            "max_emitted": False,
            "first_seen": 0,
        }
    }
    bw._write_state(str(output_dir), state)
    r = bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
    assert r is not None
    assert r["event"] == "MAX_TURNS"


def test_overshoot_still_only_emits_max_once(env):
    output_dir, _ = env
    events = []
    for _ in range(15):  # 50% beyond ceiling
        r = bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
        if r and r["event"] == "MAX_TURNS":
            events.append(r)
    assert len(events) == 1


# ---------------------------------------------------------------------------
# Multi-session correctness
# ---------------------------------------------------------------------------


def test_separate_sessions_are_independent(env):
    output_dir, _ = env
    # Exhaust session A
    for _ in range(10):
        bw.tally_and_check("sid_aaaa", "appsec-test-agent", str(output_dir))
    # Session B should still be at zero
    r = bw.tally_and_check("sid_bbbb", "appsec-test-agent", str(output_dir))
    assert r is None  # 1/10 — no threshold yet


def test_flag_file_de_duplicates_per_session(env):
    output_dir, _ = env
    # Session A hits critical
    for _ in range(9):
        bw.tally_and_check("sid_aaaa", "appsec-test-agent", str(output_dir))
    # Session B also hits critical
    for _ in range(9):
        bw.tally_and_check("sid_bbbb", "appsec-test-agent", str(output_dir))
    data = json.loads((output_dir / bw.CRITICAL_FLAG_FILENAME).read_text())
    sids = sorted(e["sid"] for e in data)
    assert sids == ["sid_aaaa", "sid_bbbb"]


# ---------------------------------------------------------------------------
# reset_session — fresh budget per dispatched stage
# ---------------------------------------------------------------------------


def test_reset_session_clears_turn_counter(env):
    """After reset, the next tool call starts the counter from 1 again."""
    output_dir, _ = env
    for _ in range(9):  # 9/10 — critical already crossed
        bw.tally_and_check("sid_aaaa", "appsec-test-agent", str(output_dir))
    bw.reset_session("sid_aaaa", str(output_dir))
    state = json.loads((output_dir / bw.STATE_FILENAME).read_text())
    assert "sid_aaaa" not in state
    # Counter restarts: a single call is 1/10, no threshold.
    r = bw.tally_and_check("sid_aaaa", "appsec-test-agent", str(output_dir))
    assert r is None


def test_reset_session_removes_flag_when_only_session(env):
    """Flag file is deleted when the reset session was the only one flagged —
    agents poll existence, so leaving an empty list would still trigger."""
    output_dir, _ = env
    for _ in range(9):
        bw.tally_and_check("sid_aaaa", "appsec-test-agent", str(output_dir))
    assert (output_dir / bw.CRITICAL_FLAG_FILENAME).is_file()
    bw.reset_session("sid_aaaa", str(output_dir))
    assert not (output_dir / bw.CRITICAL_FLAG_FILENAME).exists()


def test_reset_session_preserves_other_sessions_flag(env):
    """Resetting one session must not clear another session's flag entry."""
    output_dir, _ = env
    for _ in range(9):
        bw.tally_and_check("sid_aaaa", "appsec-test-agent", str(output_dir))
    for _ in range(9):
        bw.tally_and_check("sid_bbbb", "appsec-test-agent", str(output_dir))
    bw.reset_session("sid_aaaa", str(output_dir))
    data = json.loads((output_dir / bw.CRITICAL_FLAG_FILENAME).read_text())
    assert [e["sid"] for e in data] == ["sid_bbbb"]


def test_reset_session_never_raises_on_bad_input(env):
    output_dir, _ = env
    bw.reset_session("", str(output_dir))  # no sid
    bw.reset_session("sid_aaaa", "")  # no output_dir
    bw.reset_session("sid_aaaa", str(output_dir))  # nothing to reset


# ---------------------------------------------------------------------------
# Robustness — never raise
# ---------------------------------------------------------------------------


def test_empty_sid_returns_none(env):
    output_dir, _ = env
    assert bw.tally_and_check("", "appsec-test-agent", str(output_dir)) is None


def test_empty_output_dir_returns_none(env):
    assert bw.tally_and_check("sid12345", "appsec-test-agent", "") is None


def test_unknown_agent_uses_default_max_turns(env, monkeypatch):
    """Unknown agent => DEFAULT_MAX_TURNS (typically 250) — single tool call
    well below 75% threshold => no crossing."""
    output_dir, _ = env
    r = bw.tally_and_check("sid12345", "totally-made-up-agent", str(output_dir))
    assert r is None


def test_state_file_corrupted_resets_gracefully(env):
    output_dir, _ = env
    (output_dir / bw.STATE_FILENAME).write_text("not json{[", encoding="utf-8")
    # First call after corrupt state — should treat as empty state, start fresh
    r = bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir))
    assert r is None  # 1/10, no threshold
    state = json.loads((output_dir / bw.STATE_FILENAME).read_text())
    assert state["sid12345"]["turns"] == 1


# ---------------------------------------------------------------------------
# format_detail
# ---------------------------------------------------------------------------


def test_format_detail_includes_key_fields():
    payload = {"agent": "stride-analyzer", "turns": 36, "max": 40, "pct": 0.9}
    out = bw.format_detail(payload)
    assert "stride-analyzer" in out
    assert "36/40" in out
    assert "90%" in out


# ---------------------------------------------------------------------------
# Additional branch coverage
# ---------------------------------------------------------------------------


def test_get_max_turns_empty_name_default():
    # Empty agent name short-circuits to DEFAULT (line 66).
    assert bw.get_max_turns("") == bw.DEFAULT_MAX_TURNS


def test_get_max_turns_oserror_reading_md(env, monkeypatch):
    # OSError while reading the agent file -> continue, fall back to default
    # (lines 93-94).
    root = env[1]
    (root / "agents" / "appsec-oserr.md").write_text("---\nmaxTurns: 5\n---\n", encoding="utf-8")
    real_read = Path.read_text
    target = root / "agents" / "appsec-oserr.md"

    def boom(self, *a, **k):
        if self == target:
            raise OSError("read boom")
        return real_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", boom)
    assert bw.get_max_turns("appsec-oserr") == bw.DEFAULT_MAX_TURNS


def test_max_turns_zero_returns_none(env, monkeypatch):
    # max_turns <= 0 short-circuits tally (line 192).
    output_dir, _ = env
    monkeypatch.setattr(bw, "get_max_turns", lambda _name: 0)
    assert bw.tally_and_check("sid12345", "appsec-test-agent", str(output_dir)) is None


def test_write_state_swallows_replace_failure(env, monkeypatch):
    # os.replace failing inside _write_state must not raise (lines 126-134).
    output_dir, _ = env

    def boom(*_a, **_k):
        raise OSError("replace boom")

    monkeypatch.setattr(bw.os, "replace", boom)
    # Should not raise.
    bw._write_state(str(output_dir), {"x": 1})
    # State not persisted because write failed.
    assert not (output_dir / bw.STATE_FILENAME).exists()


def test_write_state_unlink_failure_also_swallowed(env, monkeypatch):
    # Both os.replace AND os.unlink fail — the unlink OSError is swallowed,
    # then the outer OSError handler swallows the re-raised replace error.
    output_dir, _ = env

    def boom_replace(*_a, **_k):
        raise OSError("replace boom")

    def boom_unlink(*_a, **_k):
        raise OSError("unlink boom")

    monkeypatch.setattr(bw.os, "replace", boom_replace)
    monkeypatch.setattr(bw.os, "unlink", boom_unlink)
    bw._write_state(str(output_dir), {"x": 1})  # must not raise


def test_write_flag_handles_corrupt_existing(env):
    # Existing flag file with bad JSON -> existing reset to [] (lines 152-153),
    # and a non-list JSON -> [] (lines 150-151).
    output_dir, _ = env
    flag = output_dir / bw.WARN_FLAG_FILENAME
    flag.write_text("not json{[", encoding="utf-8")
    bw._write_flag(str(output_dir), bw.WARN_FLAG_FILENAME, {"sid": "s1", "agent": "a"})
    data = json.loads(flag.read_text())
    assert data == [{"sid": "s1", "agent": "a"}]


def test_write_flag_non_list_existing_reset(env):
    output_dir, _ = env
    flag = output_dir / bw.WARN_FLAG_FILENAME
    flag.write_text('{"sid": "old"}', encoding="utf-8")  # dict, not list
    bw._write_flag(str(output_dir), bw.WARN_FLAG_FILENAME, {"sid": "s2", "agent": "a"})
    data = json.loads(flag.read_text())
    assert data == [{"sid": "s2", "agent": "a"}]


def test_write_flag_swallows_write_oserror(env, monkeypatch):
    # path.write_text raising OSError must be swallowed (lines 162-163).
    output_dir, _ = env

    real_write = Path.write_text
    flag = output_dir / bw.WARN_FLAG_FILENAME

    def boom(self, *a, **k):
        if self == flag:
            raise OSError("write boom")
        return real_write(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", boom)
    bw._write_flag(str(output_dir), bw.WARN_FLAG_FILENAME, {"sid": "s", "agent": "a"})


def test_reset_session_swallows_read_state_exception(env, monkeypatch):
    # An exception in _read_state during reset is swallowed (lines 282-283).
    output_dir, _ = env

    def boom(*_a, **_k):
        raise RuntimeError("read boom")

    monkeypatch.setattr(bw, "_read_state", boom)
    bw.reset_session("sid_aaaa", str(output_dir))  # must not raise


def test_reset_session_handles_corrupt_flag_file(env):
    # Corrupt + non-list flag content during reset -> treated as [] (lines 294-296).
    output_dir, _ = env
    flag = output_dir / bw.CRITICAL_FLAG_FILENAME
    flag.write_text("not json{[", encoding="utf-8")
    bw.reset_session("sid_aaaa", str(output_dir))
    # No remaining entries -> file unlinked.
    assert not flag.exists()


def test_reset_session_non_list_flag_unlinked(env):
    output_dir, _ = env
    flag = output_dir / bw.CRITICAL_FLAG_FILENAME
    flag.write_text('{"sid": "x"}', encoding="utf-8")  # dict, not list
    bw.reset_session("sid_aaaa", str(output_dir))
    assert not flag.exists()


def test_reset_session_unlink_oserror_swallowed(env, monkeypatch):
    # path.unlink raising OSError during reset is swallowed (lines 303-304).
    output_dir, _ = env
    flag = output_dir / bw.CRITICAL_FLAG_FILENAME
    flag.write_text("[]", encoding="utf-8")  # empty list -> triggers unlink

    real_unlink = Path.unlink

    def boom(self, *a, **k):
        if self == flag:
            raise OSError("unlink boom")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", boom)
    bw.reset_session("sid_aaaa", str(output_dir))  # must not raise
