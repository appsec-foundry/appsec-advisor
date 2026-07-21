"""Regression proofs for the defects surfaced by the 2026-07-20 juice-shop e2e run.

Each test here encodes a defect that the existing suite (72 green tests across the
budget/lazy-load/wave files) did not catch. See
docs/internal/analysis/analysis-thin-runtime-regressions-2026-07-20.md

  D3  instruction files describe script calls in prose the CLI cannot satisfy
  D6  aggregate_run_issues.py drops AGENT_ERROR / RENDER_FAILED despite promising them
  D8  agent_logger wall_secs is unresolvable across hook process boundaries
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SKILL_DIR = REPO_ROOT / "skills" / "create-threat-model"
SCRIPTS = REPO_ROOT / "scripts"

THIN_RUNTIMES = [
    SKILL_DIR / "SKILL-thin-stage1.md",
    SKILL_DIR / "SKILL-thin-stage1c.md",
    SKILL_DIR / "SKILL-thin-stage2.md",
]


# --------------------------------------------------------------------------
# D6 — aggregate_run_issues.py error matcher vs its own documented contract
# --------------------------------------------------------------------------


def test_error_extractor_matches_documented_event_list() -> None:
    """The module docstring promises four error events; the matcher must accept all.

    2026-07-20: docstring line ~20 lists TOOL_ERROR, MAX_TURNS, RENDER_FAILED,
    AGENT_ERROR, but _extract_errors matched only the first two. A real
    AGENT_ERROR ("evidence-verifier: all sampled findings unchecked") was parsed
    and silently dropped, so the run reported 0 issues.
    """
    src = (SCRIPTS / "aggregate_run_issues.py").read_text(encoding="utf-8")

    doc = re.search(r"``error``\s+—\s+(.+)", src)
    assert doc, "error-category docstring line not found"
    promised = {tok.strip() for tok in doc.group(1).split(",") if tok.strip()}

    matcher = re.search(r'if event in \((\s*"[A-Z_]+"\s*(?:,\s*"[A-Z_]+"\s*)*),?\):', src)
    assert matcher, "_extract_errors event tuple not found"
    accepted = set(re.findall(r'"([A-Z_]+)"', matcher.group(1)))

    missing = promised - accepted
    assert not missing, (
        f"aggregate_run_issues.py promises {sorted(promised)} as error events but "
        f"_extract_errors only accepts {sorted(accepted)}; dropped: {sorted(missing)}"
    )


# --------------------------------------------------------------------------
# D8 — cross-process hook state
# --------------------------------------------------------------------------


def test_dispatch_times_survive_hook_process_boundary() -> None:
    """wall_secs must not depend on in-process state.

    hooks.json runs `python3 agent_logger.py` as a FRESH PROCESS per event, so a
    module-level dict written during dispatch is always empty by the time the
    Stop hook reads it. Observed 2026-07-20: wall_secs=? on 211/211 AGENT_COMPLETE
    trace lines — the trace can never report agent wall-time.
    """
    src = (SCRIPTS / "agent_logger.py").read_text(encoding="utf-8")

    assert "_DISPATCH_TIMES" in src, "dispatch-time bookkeeping not found"

    # The store must be backed by something that outlives the process. Accept any
    # of the codebase's existing persistence idioms; reject a bare dict literal
    # that is only ever mutated in memory.
    decl = re.search(r"^_DISPATCH_TIMES.*$", src, re.M)
    assert decl, "_DISPATCH_TIMES declaration not found"

    persisted = re.search(
        r"def _dispatch_time_path\(|_DISPATCH_TIMES_FILE|_read_dispatch_times\(",
        src,
    )
    assert persisted, (
        "_DISPATCH_TIMES is an in-process dict but hooks.json spawns a new process "
        "per event (PreToolUse writes it, Stop reads it) — the value is always lost, "
        "so wall_secs resolves to '?' on every AGENT_COMPLETE. It needs a disk-backed "
        "store like the existing _active_tool_path() sidecar pattern."
    )


# --------------------------------------------------------------------------
# D3 — thin-runtime instructions must remain executable, not merely descriptive
# --------------------------------------------------------------------------


def _argparse_contract(script: str) -> tuple[set[str], list[str]]:
    """Return (accepted option strings, required-looking positionals) for a script."""
    src = (SCRIPTS / script).read_text(encoding="utf-8")
    options = set(re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', src))
    positionals = re.findall(r'add_argument\(\s*"([a-z_][a-z0-9_]*)"', src)
    return options, positionals


def test_thin_runtime_names_every_script_it_depends_on() -> None:
    """A stage file must name the script it tells the orchestrator to run.

    SKILL-thin-stage1c.md and SKILL-thin-stage2.md describe recording stats
    ("record the aggregated stats as stage 1, variant abuse-verification") without
    ever naming record_stage_stats.py — unguessable from the prose alone.
    """
    offenders = []
    for path in THIN_RUNTIMES:
        text = path.read_text(encoding="utf-8")
        mentions_stats_work = re.search(r"record .{0,40}stats|stage stats", text, re.I)
        if mentions_stats_work and "record_stage_stats.py" not in text:
            offenders.append(path.name)

    assert not offenders, (
        f"{offenders} instruct the orchestrator to record stage stats but never name "
        "record_stage_stats.py — the orchestrator cannot derive the script name"
    )


def test_thin_runtime_flags_exist_in_target_cli() -> None:
    """Every --flag a thin runtime prescribes must exist in the referenced script."""
    bad: list[str] = []
    for path in THIN_RUNTIMES:
        text = path.read_text(encoding="utf-8")
        for script in re.findall(r"([a-z_]+\.py)", text):
            if not (SCRIPTS / script).is_file():
                continue
            options, _ = _argparse_contract(script)
            if not options:
                continue
            for flag in set(re.findall(r"`(--[a-z0-9-]+)", text)):
                # Only judge flags that plausibly belong to this script: a flag is
                # a violation when NO referenced script in the file accepts it.
                all_opts: set[str] = set()
                for s2 in set(re.findall(r"([a-z_]+\.py)", text)):
                    if (SCRIPTS / s2).is_file():
                        all_opts |= _argparse_contract(s2)[0]
                if flag not in all_opts:
                    bad.append(f"{path.name}: {flag} accepted by no referenced script")
    assert not bad, "\n".join(sorted(set(bad)))


def test_record_stage_stats_pairing_rule_is_stated_where_prescribed() -> None:
    """--subagent-type and --since-iso must be passed together; say so.

    record_stage_stats.py warns and silently skips dispatch derivation when only
    one is supplied. SKILL-impl.md's pre-compaction version used
    ${VAR:+--subagent-type ... --since-iso "$VAR"} which made the violation
    structurally impossible; the compacted prose dropped that guard rail and the
    2026-07-20 run tripped the warning on every accumulate call.
    """
    for path in THIN_RUNTIMES:
        text = path.read_text(encoding="utf-8")
        if "--since-iso" not in text:
            continue
        assert "--subagent-type" in text, (
            f"{path.name} prescribes --since-iso without mentioning --subagent-type; "
            "passing one without the other silently disables dispatch derivation"
        )


def test_log_event_invocation_is_reproducible_from_instructions() -> None:
    """A stage that tells the orchestrator to log an event must show the kind.

    log_event.py rejects an event name in the kind position; `info` additionally
    requires <output_dir> info <event-name> <detail>. The compacted instruction
    named only the event, costing three failed invocations on 2026-07-20.
    """
    text = (SKILL_DIR / "SKILL-thin-stage1.md").read_text(encoding="utf-8")
    if "log_event.py" not in text:
        return

    src = (SCRIPTS / "log_event.py").read_text(encoding="utf-8")
    kinds = set(re.findall(r'"(phase-start|phase-end|step-start|step-end|info)"', src))
    assert kinds, "log_event kinds not discoverable"

    assert any(k in text for k in kinds), (
        "SKILL-thin-stage1.md tells the orchestrator to call log_event.py but never "
        f"states a valid kind (one of {sorted(kinds)}); the event name alone is "
        "rejected by the CLI"
    )


def test_referenced_scripts_positional_output_dir_not_shown_as_flag() -> None:
    """No thin runtime may prescribe --output-dir for a positional-output_dir script."""
    bad = []
    for path in THIN_RUNTIMES:
        text = path.read_text(encoding="utf-8")
        for script in set(re.findall(r"([a-z_]+\.py)", text)):
            if not (SCRIPTS / script).is_file():
                continue
            options, positionals = _argparse_contract(script)
            if "output_dir" in positionals and "--output-dir" not in options:
                if re.search(rf"{re.escape(script)}[^\n]*--output-dir", text):
                    bad.append(f"{path.name}: {script} takes positional output_dir")
    assert not bad, "\n".join(bad)


def test_subagent_type_multivalue_form_is_documented() -> None:
    """--subagent-type takes ONE comma-separated value, not a repeated flag.

    SKILL-thin-stage2.md says "pass both specialist subagent types". Repeating the
    flag makes argparse keep only the last value, so Stage-2 dispatch_count and
    wall time silently under-report — a wrong-data failure with no error.
    """
    stage2 = SKILL_DIR / "SKILL-thin-stage2.md"
    text = stage2.read_text(encoding="utf-8")
    if "--subagent-type" not in text and "subagent type" not in text.lower():
        return
    assert re.search(r"comma", text, re.I), (
        "SKILL-thin-stage2.md prescribes passing two subagent types but does not say "
        "they are comma-joined into a single --subagent-type value; a repeated flag "
        "silently keeps only the last one"
    )


def test_thin_runtimes_have_headroom_for_operational_detail() -> None:
    """Budgets must leave room to state a command, or compaction will delete it.

    Every thin surface sat at 93-96% of its ceiling on 2026-07-20, which is what
    forced exact command lines out in favour of prose.
    """
    import yaml  # noqa: PLC0415

    budgets = yaml.safe_load((REPO_ROOT / "data" / "context-budgets.yaml").read_text())
    tight = []
    for name, spec in budgets.get("surfaces", {}).items():
        if "thin_stage" not in name:
            continue
        path = REPO_ROOT / spec["path"]
        if not path.is_file() or "max_bytes" not in spec:
            continue
        pct = path.stat().st_size * 100 / spec["max_bytes"]
        if pct > 90:
            tight.append(f"{name}: {pct:.0f}% of {spec['max_bytes']}B")
    assert not tight, (
        "thin runtime surfaces are at/over 90% of budget, leaving no room to restore "
        "the exact script invocations that compaction removed: " + "; ".join(tight)
    )
