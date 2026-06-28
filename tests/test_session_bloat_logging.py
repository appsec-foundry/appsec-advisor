"""Drift guard: the pre-flight cache_read bloat detector must durably log its
detection (and the user's choice) via SESSION_BLOAT, not only warn on stderr.

The detector lives in skills/create-threat-model/SKILL-impl.md as a Bash block;
this asserts the SESSION_BLOAT wiring stays present in all three outcomes so a
slow run can later be attributed to a bloated session.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
IMPL = (REPO_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md").read_text(encoding="utf-8")


def test_log_bloat_helper_defined():
    assert "_log_bloat() {" in IMPL
    # Routes through the canonical event emitter, writes a SESSION_BLOAT event.
    assert "log_event.py" in IMPL
    assert 'SESSION_BLOAT "cache_read=$LAST_CACHE_READ' in IMPL


def test_all_three_outcomes_log_their_choice():
    # interactive continue, interactive abort, non-interactive advisory.
    assert "_log_bloat continue interactive" in IMPL
    assert "_log_bloat abort interactive" in IMPL
    assert "_log_bloat continue advisory" in IMPL


def test_abort_logs_before_exit():
    # The abort branch must record the event before it exits the run, or the
    # most interesting case (user bailed on a bloated session) is lost.
    abort_idx = IMPL.index("_log_bloat abort interactive")
    exit_idx = IMPL.index("exit 0", abort_idx)
    between = IMPL[abort_idx:exit_idx]
    assert "Aborted. Run /clear" in between


def test_detection_is_session_scoped():
    # Correctness fix: cache_read / activity must be scoped to THIS session's
    # 8-char id, not the global last SESSION_STOP (shared repo log).
    assert "CLAUDE_CODE_SESSION_ID" in IMPL
    assert 'awk -v sid="[$SID_SHORT]"' in IMPL
    # The bloat detector reads cache_read filtered by the session id.
    assert "index($0,sid) && /SESSION_STOP/" in IMPL


def test_nonempty_session_advisory_present():
    # Tier-2: a warning when the scan starts from a non-empty session.
    assert "PRIOR_ACTIVITY" in IMPL
    assert "SESSION_NONEMPTY" in IMPL
    assert "NON-EMPTY session" in IMPL


def test_bloat_message_recommends_larger_context_model():
    # The bloat error must offer the larger-context-model alternative to /clear.
    assert "1M-token) context window" in IMPL
