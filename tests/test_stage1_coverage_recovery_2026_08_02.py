"""Regression tests for the 2026-08-02 insecure-spring-app Stage-1 dead end.

The 2026-07-20 fix (tests/test_stage1_coverage_recovery_2026_07_20.py) raised the
footprint turn floor once, to a fixed cap of 48 against a 56-turn harness
ceiling. The identical failure then recurred one cap higher:

  `spring-web-app` spanned 47 files → an exhaustive pass needs 47 + 8 mandatory
  context reads + 10 write/logging reserve = 65 turns. The cap silently granted
  48; the harness killed the analyzer at exactly 56 tool calls on BOTH attempts,
  each time having written only the `seed_only` pre-seed. The dispatch gate then
  aborted the whole run.

Four defects, each covered below:

  E1 the requirement (65) was discarded by the cap with no downstream signal,
     so the analyzer was told to read a component that could not be read
  E2 the harness ceiling did not track the cap plus a wrap-up reserve
  E3 the retry reused the identical budget, so a budget-caused death repeated
     deterministically -- the gate's own abort text said as much
  E4 the shared per-session turn counter was attributed to the FIRST agent ever
     registered for the run, so every dispatch resolved `threat-analyst`
     (maxTurns 300) and the watchdog could never observe a sub-agent at all
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_stride_dispatch_manifest as manifest  # noqa: E402
import classify_component  # noqa: E402
import stride_dispatch_waves as waves  # noqa: E402

# The component that broke, reduced to its two governing numbers.
SPRING_WEB_APP_FILES = 47
KILLED_AT_TURNS = 56


# --------------------------------------------------------------------------
# E1 — a clamped budget must never be handed out silently
# --------------------------------------------------------------------------


def test_the_component_that_died_now_gets_a_budget_it_can_finish_in() -> None:
    """47 files must not be dispatched with fewer turns than reading them costs."""
    needed = classify_component.footprint_turns_needed(SPRING_WEB_APP_FILES)
    granted, _reason, clamped = classify_component._footprint_turn_floor(
        SPRING_WEB_APP_FILES, classify_component.TURN_BUDGETS["standard"]["complex"]
    )

    assert needed == 65, "footprint arithmetic changed; re-derive this regression"
    assert not clamped, "a 47-file component should fit without sampling"
    assert granted >= needed, (
        f"granted {granted} turns for a component whose reads cost {needed} — "
        "this is exactly the silent clamp that killed spring-web-app twice"
    )
    assert granted > KILLED_AT_TURNS, (
        f"granted {granted} turns, but the old harness ceiling was {KILLED_AT_TURNS}; "
        "the component must be able to outlive the budget that killed it"
    )


def test_clamping_is_reported_instead_of_silent() -> None:
    """Beyond the cap, clamping is legitimate — but it must be announced."""
    wide = classify_component._FOOTPRINT_TURN_CAP  # far more files than the cap allows
    granted, reason, clamped = classify_component._footprint_turn_floor(wide * 10, 31)

    assert clamped is True, "an unmeetable requirement must set budget_clamped"
    assert granted <= classify_component._FOOTPRINT_TURN_CAP
    assert "sampling" in reason.lower(), (
        "the clamp must say so in the reason string; a bare number is what made "
        "the 2026-08-02 failure undiagnosable from the manifest"
    )


def test_classify_always_exposes_budget_clamped() -> None:
    """Every classify() return path carries the key, so consumers can rely on it."""
    cases = [
        classify_component.classify("auth-service", "", 8, "standard", file_count=9000),
        classify_component.classify("svc", "", 1, "standard"),  # trivial-skip path
        classify_component.classify("web", "", 9, "standard", file_count=9000),
    ]
    for result in cases:
        assert "budget_clamped" in result, f"missing budget_clamped in {result['complexity']} path"
    assert cases[0]["budget_clamped"] is True
    assert cases[2]["budget_clamped"] is True


def test_manifest_carries_the_sampling_signal_to_the_dispatch(tmp_path: Path) -> None:
    """sampling_required/file_count must reach the manifest, not stop at classify."""
    for i in range(40):
        (tmp_path / f"f{i}.java").write_text("x", encoding="utf-8")

    turns, sampling, count = manifest._component_turn_budget(tmp_path, ["*.java"], 31)
    assert count == 40
    assert turns >= classify_component.footprint_turns_needed(40)
    assert sampling is False, "40 files fit the cap; sampling must not be demanded"

    # A cheap-stride screening pass is sampling by construction.
    cheap_turns, cheap_sampling, _ = manifest._component_turn_budget(tmp_path, ["*.java"], 31, cheap=True)
    assert cheap_turns == manifest.CHEAP_STRIDE_TURNS
    assert cheap_sampling is True, "an 8-turn screen over 40 files is sampling; say so"


# --------------------------------------------------------------------------
# E2 — the harness ceiling must track the widest budget the skill can emit
# --------------------------------------------------------------------------


def test_harness_ceiling_covers_cap_and_retry_escalation() -> None:
    """A soft target above the frontmatter ceiling is unreachable by construction."""
    import re

    text = (REPO_ROOT / "agents" / "appsec-stride-analyzer.md").read_text(encoding="utf-8")
    m = re.search(r"^maxTurns:\s*(\d+)", text, re.M)
    assert m, "maxTurns not found in analyzer frontmatter"
    ceiling = int(m.group(1))

    highest = max(
        classify_component._FOOTPRINT_TURN_CAP,
        classify_component._RETRY_TURN_CAP,
        max(b["complex"] for b in classify_component.TURN_BUDGETS.values()),
    )
    assert ceiling > highest, (
        f"harness ceiling {ceiling} does not exceed the highest derivable budget "
        f"{highest}; a component granted that budget is killed before it can spend it"
    )
    # The reserve must be big enough for six per-category flushes plus wrap-up.
    assert ceiling - highest >= 8, (
        f"only {ceiling - highest} turns between the widest budget and the hard "
        "kill — too thin for the per-category flushes the write contract requires"
    )


# --------------------------------------------------------------------------
# E3 — a retry must not repeat the dispatch that already failed
# --------------------------------------------------------------------------


def test_retry_escalates_the_turn_budget() -> None:
    base = 48
    raised = classify_component.escalated_retry_turns(base)
    assert raised > base, "attempt 2 with attempt 1's budget dies the same way"
    assert raised <= classify_component._RETRY_TURN_CAP


def test_claim_raises_the_budget_on_the_second_attempt() -> None:
    """The wave dispatcher applies the escalation, not just the helper."""
    component = {"component_id": "wide", "max_turns": 48}
    escalated = waves._escalated_component(component)

    assert escalated["max_turns"] > 48
    assert escalated["retry_budget_escalated"] is True
    assert escalated["sampling_required"] is True, (
        "a component that already failed once must be told to sample rather than "
        "gamble that the larger budget happens to be enough"
    )


def test_escalation_never_mutates_the_manifest_entry() -> None:
    """Mutating in place changes _fingerprint(manifest) and breaks every resume.

    The wave's component entries ARE the manifest's dicts; validate_plan matches
    the persisted plan against that fingerprint.
    """
    component = {"component_id": "wide", "max_turns": 48}
    waves._escalated_component(component)

    assert component == {"component_id": "wide", "max_turns": 48}, (
        "escalation leaked into the manifest entry — a later resume would fail "
        "with 'wave plan does not match the current dispatch manifest'"
    )


def test_budget_escalation_is_best_effort() -> None:
    """A malformed entry must not break the claim — dispatch beats no dispatch."""
    for bad in ({"component_id": "x"}, {"component_id": "x", "max_turns": "nope"}):
        assert waves._escalated_component(bad) == bad  # must not raise


# --------------------------------------------------------------------------
# E4 — shared-session attribution
# --------------------------------------------------------------------------


def test_session_agent_lookup_returns_the_most_recent_registration(tmp_path, monkeypatch) -> None:
    """First-match made every STRIDE dispatch report as threat-analyst."""
    import agent_logger

    map_file = tmp_path / ".session-agent-map"
    map_file.write_text(
        "abcd1234=threat-analyst\nabcd1234=recon-scanner\nabcd1234=stride-analyzer\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(agent_logger, "_session_map_path", lambda: str(map_file))

    assert agent_logger._lookup_session_agent("abcd1234") == "stride-analyzer"
    assert agent_logger._lookup_session_agents("abcd1234") == [
        "threat-analyst",
        "recon-scanner",
        "stride-analyzer",
    ]


def test_budget_scope_uses_the_widest_registered_budget(tmp_path, monkeypatch) -> None:
    """The shared counter must not be measured against a sub-agent's small cap.

    Otherwise a parallel STRIDE wave trips .budget-critical from its own
    aggregate traffic and forces every in-flight analyzer to wrap up early.
    """
    import agent_logger

    map_file = tmp_path / ".session-agent-map"
    map_file.write_text(
        "abcd1234=threat-analyst\nabcd1234=stride-analyzer\n", encoding="utf-8"
    )
    monkeypatch.setattr(agent_logger, "_session_map_path", lambda: str(map_file))

    scope = agent_logger._budget_scope_agent("abcd1234")
    assert scope == "threat-analyst", (
        "budget scope must be the widest registered agent, not the most recent"
    )


def test_tally_uses_budget_agent_when_supplied(tmp_path) -> None:
    """budget_agent overrides which maxTurns the shared counter is measured on."""
    import budget_watchdog

    out = str(tmp_path)
    narrow = budget_watchdog.get_max_turns("appsec-stride-analyzer")
    wide = budget_watchdog.get_max_turns("appsec-threat-analyst")
    assert wide > narrow, "fixture assumption: orchestrator budget is the wider one"

    budget_watchdog.tally_and_check("sid00001", "stride-analyzer", out, budget_agent="threat-analyst")
    state = budget_watchdog._read_state(out)

    assert state["sid00001"]["max_turns"] == wide
    assert state["sid00001"]["agent"] == "stride-analyzer", "reporting name stays the caller"
