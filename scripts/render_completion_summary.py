#!/usr/bin/env python3
"""Render the Completion Summary block for create-threat-model.

Replaces ~350 lines of Bash-heredoc prose in ``skills/create-threat-model/
SKILL.md``. The skill now calls this script instead of walking the LLM
through each extraction step, which:

  1. removes ~7 k tokens from the skill's inlined context on every run,
  2. makes the summary rendering unit-testable,
  3. guarantees byte-identical output across runs with the same inputs.

Two completion modes are supported:

  ``--mode-dry-run``  Truncated preview rendered to stdout, no log /
                      token data (temp OUTPUT_DIR is about to be wiped).
  (default)           Full completion with Files, Change Summary,
                      Metrics, Run Statistics, Next Steps, Log Files.

The script is self-contained — no LLM judgement, no external APIs except
the sibling ``verify_run_costs.py`` (for delta-based token accounting).
All other information is read from ``$OUTPUT_DIR``: ``threat-model.md``,
``threat-model.yaml``, ``.agent-run.log``, ``.hook-events.log``.

Usage:
    render_completion_summary.py \\
        --output-dir PATH --repo-root PATH [other flags]

Flags:
    --output-dir PATH           OUTPUT_DIR written by the orchestrator.
    --repo-root PATH            REPO_ROOT (used for the Repository header).
    --mode {full,incremental,rebuild,dry-run}
                                Run mode from the skill's resolution.
                                (Defaults to ``full``.)
    --write-yaml / --no-write-yaml
    --write-sarif / --no-write-sarif
    --write-pentest-tasks / --no-write-pentest-tasks
    --check-requirements / --no-check-requirements
    --architect-review / --no-architect-review
    --reasoning-model {opus-cheap,sonnet,opus,sonnet-economy,haiku-economy}
                                Used only to decide whether the "re-run
                                with --reasoning-model opus" Next Steps
                                line should appear (Sonnet-only runs).
    --assessment-depth {quick,standard,thorough}
                                Displayed in the Run block.
    --patch-placeholders        When set, rewrite ``_pending_`` tokens in
                                the ``## Appendix: Run Statistics``
                                section of threat-model.md in place with
                                the extracted durations / models.

Exit codes:
    0 — summary printed successfully
    2 — bad inputs (OUTPUT_DIR missing, threat-model.md missing, etc.)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

import run_timing  # sibling script — scripts/ is on sys.path (script dir / conftest)

BANNER_WIDTH = 62
RULE = "═" * BANNER_WIDTH
SECTION_RULE = "-" * 59  # matches the `--- Foo ---` dividers in the template


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml as _yaml
    except ImportError:
        return {}
    try:
        data = _yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, _yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _has_cost_signal(output_dir: Path) -> bool:
    """Cheaply detect whether verify_run_costs.py can have useful input."""
    signal_tokens = (
        "SESSION_STOP",
        "ASSESSMENT_TOKENS",
        "cost=$",
        "cache_write=",
        "cache_read=",
        "input=",
        "output=",
    )
    for name in (".hook-events.log", ".agent-run.log"):
        text = _load_text(output_dir / name)
        if text and any(token in text for token in signal_tokens):
            return True
    return False


# ---------------------------------------------------------------------------
# Metric extraction — from threat-model.yaml / threat-model.md
# ---------------------------------------------------------------------------


_MD_COMPONENT_RE = re.compile(r"^###\s+2\.3\s+", re.MULTILINE)


def extract_metrics(yaml_data: dict, md_text: str) -> dict[str, Any]:
    """Extract counts from yaml (authoritative) + md (fallback)."""
    # Threats.
    threats = yaml_data.get("threats") or []
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in threats:
        sev = (t.get("risk") or t.get("severity") or "").strip()
        sev_title = sev[:1].upper() + sev[1:].lower() if sev else ""
        if sev_title in by_sev:
            by_sev[sev_title] += 1

    # Components — prefer yaml length.
    components = yaml_data.get("components") or []
    n_components = len(components)
    if n_components == 0 and md_text:
        n_components = len(_MD_COMPONENT_RE.findall(md_text))

    # Controls — count status badges in yaml if present, otherwise scan md.
    controls = yaml_data.get("security_controls") or yaml_data.get("controls") or []
    # All five buckets of effectiveness_taxonomy (sections-contract.yaml) — the
    # `unsafe` bucket was previously omitted, so a control rated Unsafe counted
    # toward controls_total but appeared in no sub-bucket and the breakdown did
    # not reconcile with the total (juice-shop 2026-06: 38 cataloged rendered as
    # 3/7/2/23 = 35, dropping 3 Unsafe).
    control_status = {"adequate": 0, "partial": 0, "weak": 0, "unsafe": 0, "missing": 0}
    for c in controls:
        eff = (c.get("effectiveness") or c.get("status") or "").strip().lower()
        if eff in control_status:
            control_status[eff] += 1

    # Requirements compliance — present only when the skill ran with
    # --requirements. Not in this run; we still expose the field so the
    # renderer can decide.
    req = yaml_data.get("requirements_compliance") or {}
    req_counts = {
        "pass": req.get("pass") or 0,
        "fail": req.get("fail") or 0,
        "partial": req.get("partial") or 0,
        "total": req.get("total") or 0,
    }

    mitigations = yaml_data.get("mitigations") or []

    return {
        "threats_total": len(threats),
        "threats_by_sev": by_sev,
        "n_components": n_components,
        "controls_total": len(controls),
        "control_status": control_status,
        "requirements": req_counts,
        "mitigations_total": len(mitigations),
    }


# ---------------------------------------------------------------------------
# Change Summary — extracts the first changelog entry if a baseline existed
# ---------------------------------------------------------------------------


def _sample_ids(ids: list[str], note_fmt=None, max_items: int = 5) -> str:
    if not ids:
        return ""
    shown = [note_fmt(i) if note_fmt else i for i in ids[:max_items]]
    extra = len(ids) - max_items
    suffix = f", +{extra} more" if extra > 0 else ""
    return ", ".join(shown) + suffix


_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _severity_label(threat: dict | None) -> str:
    if not threat:
        return ""
    raw = (threat.get("risk") or threat.get("severity") or "").strip()
    label = raw[:1].upper() + raw[1:].lower() if raw else ""
    return label if label in _SEVERITY_ORDER else raw


def _threat_title(threat: dict | None) -> str:
    if not threat:
        return ""
    title = (threat.get("title") or threat.get("name") or "").strip()
    if title:
        return title
    scenario = (threat.get("scenario") or threat.get("description") or "").strip()
    return scenario[:80].rstrip()


def _threat_index(yaml_data: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for threat in yaml_data.get("threats") or []:
        tid = threat.get("id") or threat.get("t_id")
        if tid:
            out[str(tid)] = threat
    return out


def _sort_threat_ids(ids: list[str], by_id: dict[str, dict]) -> list[str]:
    def key(tid: str) -> tuple[int, str]:
        sev = _severity_label(by_id.get(tid))
        return (_SEVERITY_ORDER.get(sev, 99), tid)

    return sorted(ids, key=key)


def _format_threat_delta_entries(
    ids: list[str],
    by_id: dict[str, dict],
    notes_by_id: dict | None = None,
    max_items: int = 3,
) -> tuple[list[str], int]:
    notes_by_id = notes_by_id or {}
    lines: list[str] = []
    for tid in _sort_threat_ids(ids, by_id)[:max_items]:
        threat = by_id.get(tid)
        sev = _severity_label(threat)
        title = _threat_title(threat)
        note = str(notes_by_id.get(tid) or "").strip()
        parts = [tid]
        if sev:
            parts.append(sev)
        if title:
            parts.append(title)
        elif note:
            parts.append(note)
        if note and title:
            parts.append(f"({note})")
        lines.append(" ".join(parts))
    return lines, max(0, len(ids) - max_items)


def _format_resolved_delta_entries(
    ids: list[str],
    reasons_by_id: dict | None = None,
    max_items: int = 3,
) -> tuple[list[str], int]:
    reasons_by_id = reasons_by_id or {}
    lines: list[str] = []
    for tid in ids[:max_items]:
        reason = str(reasons_by_id.get(tid) or "").strip()
        lines.append(f"{tid} {reason}".rstrip())
    return lines, max(0, len(ids) - max_items)


def extract_change_summary(yaml_data: dict) -> Optional[dict]:
    """Returns None when no baseline / first-run, else a dict ready to
    feed into ``render_change_summary``."""
    cl = yaml_data.get("changelog") or []
    if not cl:
        return None
    e = cl[0]
    if not isinstance(e, dict):
        return None
    added_ids = (e.get("added") or {}).get("threats") or []
    changed_ids = (e.get("changed") or {}).get("threats") or []
    resolved_ids = (e.get("resolved") or {}).get("threats") or []

    # First-run full assessment: every threat appears as "added" by definition,
    # because the changelog entry was created against a non-existent baseline.
    # Rendering "Prior baseline: full run from <today>, commit n/a / Added: N"
    # is semantically empty and misleads the user into thinking there was a
    # prior state. Suppress unconditionally on first-run mode=full with
    # version==1 (or missing) and no baseline_sha and exactly one changelog
    # entry on file.
    mode_val = e.get("mode")
    version_val = e.get("version")
    baseline_val = e.get("baseline_sha")
    # version may load as int 1 (canonical) or string "1" (some YAML loaders /
    # hand-edited files); coerce to a comparable form so both signal a first
    # run.
    try:
        version_int = int(version_val) if version_val is not None else None
    except (TypeError, ValueError):
        version_int = None
    is_first_run_full = (
        mode_val == "full" and (version_int == 1 or version_int is None) and not baseline_val and len(cl) == 1
    )
    if is_first_run_full:
        return None

    # An "iterative" run (incremental git-baseline, or a full run that diffed
    # against a prior fingerprinted entry) ALWAYS reports its threat delta on
    # the console — including an explicit "no new / no resolved" line when
    # nothing changed. Non-iterative full snapshots keep the old suppression.
    basis = e.get("delta_basis")
    is_iterative = basis in ("incremental", "fingerprint") or mode_val == "incremental" or bool(baseline_val)

    # Resolved on a full fingerprint delta are carried as prior fingerprints
    # (T-IDs aren't stable across full runs), not as resolved.threats.
    resolved_fps = (e.get("resolved") or {}).get("fingerprints") or []
    resolved_fp_labels = [(fp.split("|")[2] or fp).strip() for fp in resolved_fps if isinstance(fp, str)]

    # Only render when the entry has delta data. First-run full assessments
    # produce a changelog[0] but with empty deltas — skip those, but never skip
    # an iterative run (the user asked for output even when nothing changed).
    has_delta = bool(added_ids or changed_ids or resolved_ids or resolved_fp_labels)
    if (
        not is_iterative
        and not has_delta
        and not (e.get("reanalyzed_components") or e.get("carried_forward_components"))
    ):
        return None

    notes_by_id = (e.get("changed") or {}).get("notes_by_id") or {}
    reasons_by_id = (e.get("resolved") or {}).get("reason_by_id") or {}
    threats_by_id = _threat_index(yaml_data)

    changed_fmt = lambda i: f"{i} ({notes_by_id[i]})" if i in notes_by_id else i
    resolved_fmt = lambda i: f"{i} ({reasons_by_id[i]})" if i in reasons_by_id else i

    added_entries, added_more = _format_threat_delta_entries(added_ids, threats_by_id)
    changed_entries, changed_more = _format_threat_delta_entries(changed_ids, threats_by_id, notes_by_id)
    resolved_entries, resolved_more = _format_resolved_delta_entries(resolved_ids, reasons_by_id)

    baseline_sha = e.get("baseline_sha") or "n/a"
    return {
        "added_n": len(added_ids),
        "changed_n": len(changed_ids),
        "resolved_n": len(resolved_ids),
        "added_ids": _sample_ids(added_ids),
        "changed_ids": _sample_ids(changed_ids, changed_fmt),
        "resolved_ids": _sample_ids(resolved_ids, resolved_fmt),
        "reanalyzed_n": len(e.get("reanalyzed_components") or []),
        "carried_n": len(e.get("carried_forward_components") or []),
        "cl_mode": e.get("mode", "?"),
        "is_iterative": is_iterative,
        # Full ID lists (no titles) for the console New/Resolved lines. Resolved
        # IDs are plain (removed findings have no current anchor); a full
        # fingerprint delta falls back to the prior fingerprint labels.
        "added_id_list": list(added_ids),
        "resolved_id_list": list(resolved_ids) or resolved_fp_labels,
        "baseline_short": baseline_sha[:12] if baseline_sha != "n/a" else "n/a",
        # Run sequence number is positional (newest entry = total count), NOT
        # the entry's constant schema-version field. The newest entry is cl[0].
        "version": len(cl),
        "date": e.get("date", "?"),
        "changed_files": e.get("changed_files"),
        "added_entries": added_entries,
        "added_more": added_more,
        "changed_entries": changed_entries,
        "changed_more": changed_more,
        "resolved_entries": resolved_entries,
        "resolved_more": resolved_more,
    }


# ---------------------------------------------------------------------------
# Run statistics — durations + per-phase timeline from .agent-run.log
# ---------------------------------------------------------------------------


_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
_PHASE_START_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?PHASE_START\s+\[Phase\s+"
    r"(\d+[a-z]?)/\d+\]\s+[▶]*\s*(.+?)(?:\s*[…\(]|$)"
)
# Fix #3 root cause — separate regex that captures the AGENT emitting the
# PHASE_START line. Stage 1 Phase 11 is emitted by ``threat-analyst``,
# Stage 2 Phase 11 by ``threat-renderer``. A static phase→agent map cannot
# distinguish them; the log line itself is the source of truth. Run this
# second regex against the same line as _PHASE_START_RE to pair (phase,
# emitter) without changing the existing group-indexed call sites.
_PHASE_AGENT_RE = re.compile(
    r"\s(?P<agent>[a-z0-9\-]+)\s+PHASE_START\s+\[Phase\s+"
    r"(?P<phase>\d+[a-z]?)/"
)
_PHASE_END_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?PHASE_END\s+\[Phase\s+"
    r"(\d+[a-z]?)/\d+\]"
)
_AGENT_INVOKE_RE = re.compile(
    r"AGENT_(?:INVOKE|DISPATCH|SPAWN)\s+(?:\[.*?\]\s+)?"
    r"(?:appsec-advisor:)?(?:appsec-)?(?P<agent>[a-z0-9\-]+)\s+model=(?P<model>[a-z0-9\-]+)"
)

# Model-short-name mapping. Orchestrator and hooks log short names
# (``sonnet``, ``opus``), but the user-facing display convention is
# ``sonnet-4-6`` / ``opus-4-7`` so it matches the REASONING_MODEL resolver.
_MODEL_NORMALIZE = {
    "sonnet": "sonnet-4-6",
    "opus": "opus-4-7",
    "haiku": "haiku-4-5",
    "claude-sonnet-4-6": "sonnet-4-6",
    "claude-opus-4-7": "opus-4-7",
    "claude-haiku-4-5": "haiku-4-5",
}


def _normalize_model(name: str) -> str:
    if not name:
        return "?"
    return _MODEL_NORMALIZE.get(name, name)


# AGENT_START lines in .agent-run.log carry the full model id inside the
# message body, e.g. ``(model: claude-sonnet-4-6)``. Parse that as a
# secondary source so Stage 3 (which writes AGENT_START but no
# corresponding AGENT_INVOKE) still shows up in the roster.
_AGENT_START_RE = re.compile(
    r"\s(?P<agent>[a-z0-9\-]+)\s+AGENT_START\s+.*?"
    r"\(model:\s*(?P<model>claude-[a-z0-9\-]+)\)"
)

# Sub-agents (recon-scanner, stride-analyzer, triage-validator, context-resolver,
# threat-merger, evidence-verifier, config-scanner) log themselves as
# ``<agent>  AGENT_INVOKE  <message> (model: claude-<id>)``. Pattern uses
# the parenthetical form rather than ``model=<id>`` and was not covered by
# _AGENT_INVOKE_RE — leaving every sub-agent row in the Run Statistics block
# rendered as ``(?)``. Fix #4.
_AGENT_INVOKE_PAREN_RE = re.compile(
    r"\s(?P<agent>[a-z0-9\-]+)\s+AGENT_INVOKE\s+.*?"
    r"\(model:\s*(?P<model>claude-[a-z0-9\-]+)\)"
)


def _iso_to_epoch(ts: str) -> int:
    try:
        return int(_dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc).timestamp())
    except ValueError:
        return 0


def _fmt_duration(seconds: int) -> str:
    if seconds < 0:
        return "0m 00s"
    return f"{seconds // 60}m {seconds % 60:02d}s"


def extract_run_statistics(output_dir: Path, yaml_data: dict) -> dict:
    """Compute assessment / QA / architect durations + per-phase timeline.

    Precedence for the assessment duration:
      1. ``meta.analysis_duration_seconds`` from threat-model.yaml
      2. ``ASSESSMENT_END ... completed in X min Y s`` in .agent-run.log
      3. None (omit from output)

    Precedence for the **total** duration (the headline figure):
      1. Sum of ``duration_ms`` across all stages in ``.stage-stats.jsonl``
         when the file exists. This is the only source that captures every
         dispatched agent (Stage 1 orchestrator, Stage 2 renderer, Stage 3
         QA, Stage 4 architect, plus REPAIR_MODE iterations) — the legacy
         path below was assess + qa + arch only and consequently missed the
         renderer + repair iterations entirely on real runs.
      2. Legacy fallback: ``assess_secs + qa_secs + arch_secs`` (computed
         further down). Used when the jsonl file is absent (older runs,
         dry-run, or the skill aborted before record_stage_stats fired).
    """
    log_path = output_dir / ".agent-run.log"
    log_text = _load_text(log_path)

    stats: dict[str, Any] = {
        "assess_secs": None,
        "qa_secs": None,
        "arch_secs": None,
        "phases": [],
        # Per-stage rows from .stage-stats.jsonl (authoritative). Each entry:
        # (stage:int, variant:str, name:str, agent:str, model:str, secs:int).
        # Rendered as the per-stage breakdown — preferred over the log-derived
        # ``phases`` list, which is lossy in the parallel-STRIDE path.
        "stage_rows": [],
        "agents": {},
        # Authoritative total wall-clock when stage-stats.jsonl is present.
        # render_run_statistics prefers this over assess+qa+arch when set.
        "total_secs_from_stages": None,
        # True end-to-end wall-clock of the whole scan (skill start → completion).
        # Distinct from total_secs_from_stages, which only sums per-stage agent
        # compute and therefore excludes the orchestration gaps between
        # dispatches + the preamble. Written by the skill at completion.
        "wall_secs": None,
        # Net-vs-wall breakdown with standby/suspend isolated (run_timing.py).
        # Used to render the net compute / idle / standby lines so a run that
        # sat in machine standby reports an honest net figure instead of a
        # wall-clock dominated by sleep. Single source shared with the skill's
        # last_run_seconds writer.
        "timing": run_timing.compute_timing(output_dir),
    }

    # Total wall-clock from .stage-stats.jsonl. Lines are JSON objects with
    # a `duration_ms` field; sum them across all recorded stages.
    stage_jsonl = output_dir / ".stage-stats.jsonl"
    if stage_jsonl.is_file():
        total_ms = 0
        try:
            for line in stage_jsonl.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                ms = rec.get("duration_ms")
                if isinstance(ms, (int, float)) and ms > 0:
                    total_ms += int(ms)
                stats["stage_rows"].append(
                    (
                        rec.get("stage"),
                        rec.get("variant") or "",
                        rec.get("name") or "",
                        (rec.get("agent") or "—").split(":")[-1],
                        rec.get("model") or "?",
                        int(ms) // 1000 if isinstance(ms, (int, float)) and ms > 0 else 0,
                    )
                )
        except OSError:
            total_ms = 0
        if total_ms > 0:
            stats["total_secs_from_stages"] = total_ms // 1000

    # True end-to-end wall-clock — a single integer written by the skill at
    # completion (now - .scan-start-epoch). Read here as a precomputed value so
    # this function stays deterministic (no time.time()). The skill owns the
    # timing because the .agent-run.log ASSESSMENT_START line gets overwritten
    # by each analyst dispatch under the parallel-STRIDE split, so a
    # log-derived start under-counts.
    wall_path = output_dir / ".scan-wall-seconds"
    if wall_path.is_file():
        try:
            w = int(wall_path.read_text(encoding="utf-8").strip() or "0")
            if w > 0:
                stats["wall_secs"] = w
        except (OSError, ValueError):
            pass

    meta = yaml_data.get("meta") or {}
    assess_secs = meta.get("analysis_duration_seconds")
    if isinstance(assess_secs, int) and assess_secs > 0:
        stats["assess_secs"] = assess_secs
    elif log_text:
        m = re.search(r"ASSESSMENT_END.*?completed in (\d+)\s*min\s*(\d+)\s*s", log_text)
        if m:
            stats["assess_secs"] = int(m.group(1)) * 60 + int(m.group(2))
        else:
            # Fix #9 root cause — when no "completed in X min Y s" phrase is
            # in the log (because STAGE1_PHASE_LIMIT=10b stops Stage 1 with
            # an "Stage-1 complete (...) — lock retained for Stage-2" message
            # instead), use the FIRST ASSESSMENT_END timestamp as the end
            # marker. Falling back to "last PHASE_END" extends past Stage 1
            # into Stage 2's phase events and over-counts by 13-15 minutes
            # (40m 05s observed in the 2026-05-21 juice-shop run where the
            # true Stage 1 duration was 26m 25s).
            start_m = re.search(
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*?ASSESSMENT_START",
                log_text,
            )
            assessment_end_m = re.search(
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*?ASSESSMENT_END",
                log_text,
            )
            end_match = assessment_end_m
            if not end_match:
                # No ASSESSMENT_END at all — orchestrator died mid-run.
                # Use last PHASE_END/START as the best-effort approximation
                # (this WAS the old behaviour, retained only for the genuine
                # crash case, not the STAGE1_PHASE_LIMIT case).
                last_phase_m = None
                for mm in re.finditer(
                    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*?PHASE_(?:END|START)",
                    log_text,
                ):
                    last_phase_m = mm
                end_match = last_phase_m
            if start_m and end_match:
                start_ep = _iso_to_epoch(start_m.group(1))
                end_ep = _iso_to_epoch(end_match.group(1))
                if start_ep and end_ep >= start_ep:
                    stats["assess_secs"] = end_ep - start_ep

    # QA duration from AGENT_START → AGENT_COMPLETE timestamps.
    qa_start_m = re.search(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?qa-reviewer\s+AGENT_START",
        log_text,
    )
    qa_end_m = re.search(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?qa-reviewer\s+"
        r"(?:AGENT_COMPLETE|CHECK_END)",
        log_text[::-1] if False else log_text,  # straightforward forward scan
    )
    # The "end" line is whichever comes last.
    qa_end_ms = list(
        re.finditer(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?qa-reviewer\s+"
            r"(?:AGENT_COMPLETE|CHECK_END)",
            log_text,
        )
    )
    if qa_start_m and qa_end_ms:
        qa_start = _iso_to_epoch(qa_start_m.group(1))
        qa_end = _iso_to_epoch(qa_end_ms[-1].group(1))
        if qa_start and qa_end >= qa_start:
            stats["qa_secs"] = qa_end - qa_start

    # Architect duration likewise.
    arch_start_m = re.search(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?architect-reviewer\s+AGENT_START",
        log_text,
    )
    arch_end_ms = list(
        re.finditer(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?architect-reviewer\s+"
            r"(?:AGENT_COMPLETE|CHECK_END)",
            log_text,
        )
    )
    if arch_start_m and arch_end_ms:
        a_start = _iso_to_epoch(arch_start_m.group(1))
        a_end = _iso_to_epoch(arch_end_ms[-1].group(1))
        if a_start and a_end >= a_start:
            stats["arch_secs"] = a_end - a_start

    # Per-phase timeline.  Pair PHASE_START with the next PHASE_END for the
    # same phase-id; ignore overlapping "inline" entries where start and end
    # share the same timestamp.
    # Fix #3 root cause — also capture the agent that EMITTED each PHASE_START
    # so the rendering loop can show "threat-analyst" / "threat-renderer"
    # distinctly when the same phase-id appears twice (Stage 1 vs Stage 2).
    # Per-phase STACK of unmatched PHASE_START tuples, keyed by phase_id. A
    # stack (not a single overwrite-able value) so each PHASE_END consumes its
    # matching START via pop(). This prevents a stray/duplicate PHASE_END — e.g.
    # a Phase-11 substep close mislabeled "[Phase 10b/11]" in STAGE1_PHASE_LIMIT
    # =10b mode — from re-pairing against an already-closed START and inventing a
    # phantom "(run 2)" whose duration absorbs the following phase's wall time
    # (the 2026-06-11 juice-shop "Triage Validation (run 2) 5m17s" artifact).
    # Mirrors the proven stack-with-pop pairing in
    # compose_threat_model._scrape_phase_durations. The legitimate dual-stage
    # case (same phase-id appearing once in Stage 1 and once in Stage 2, each
    # with its own START+END) still yields two correctly-paired durations.
    starts: dict[str, list[tuple[int, str, str]]] = {}  # phase_id -> [(epoch, desc, agent)]
    phase_durations: list[tuple[str, str, int, str]] = []  # (id, desc, secs, agent)
    for line in log_text.splitlines():
        m = _PHASE_START_RE.search(line)
        if m:
            am = _PHASE_AGENT_RE.search(line)
            emitter = am.group("agent") if am else ""
            starts.setdefault(m.group(2), []).append((_iso_to_epoch(m.group(1)), m.group(3).strip(), emitter))
            continue
        m = _PHASE_END_RE.search(line)
        if m:
            phase_id = m.group(2)
            end_ep = _iso_to_epoch(m.group(1))
            stack = starts.get(phase_id)
            if stack:
                start_ep, desc, agent = stack.pop()
                phase_durations.append((phase_id, desc, end_ep - start_ep, agent))
    stats["phases"] = phase_durations

    # Agent roster — union of AGENT_START (agent-run.log) and AGENT_SPAWN /
    # AGENT_INVOKE (hook-events.log). The hook-events log is authoritative
    # for the model assignment because it captures the Agent tool's
    # `model=` parameter at dispatch time; the agent-run log's AGENT_START
    # only exists when the agent itself emitted a log line (so e.g. a
    # crashed orchestrator leaves no trace there).
    hook_text = _load_text(output_dir / ".hook-events.log")
    combined = log_text + "\n" + hook_text
    for m in _AGENT_INVOKE_RE.finditer(combined):
        agent = m.group("agent")
        stats["agents"][agent] = _normalize_model(m.group("model"))
    for m in _AGENT_START_RE.finditer(combined):
        agent = m.group("agent")
        # Don't overwrite a name we already learned from the hook — the
        # AGENT_START line has richer model ids but the hook's short
        # form is canonical for display. Only fill gaps.
        if agent not in stats["agents"]:
            stats["agents"][agent] = _normalize_model(m.group("model"))
    # Sub-agents (AGENT_INVOKE with "(model: ...)" form). Only fill gaps so
    # the orchestrator-level mapping wins for the top-level agent.
    for m in _AGENT_INVOKE_PAREN_RE.finditer(combined):
        agent = m.group("agent")
        if agent not in stats["agents"]:
            stats["agents"][agent] = _normalize_model(m.group("model"))
    return stats


# ---------------------------------------------------------------------------
# Token & cost — delegate to verify_run_costs.py
# ---------------------------------------------------------------------------


def extract_costs(output_dir: Path, plugin_root: Path) -> Optional[dict]:
    """Return the parsed JSON from verify_run_costs.py, or None on failure."""
    script = plugin_root / "scripts" / "verify_run_costs.py"
    if not script.is_file():
        return None
    if not _has_cost_signal(output_dir):
        return None
    try:
        r = subprocess.run(
            ["python3", str(script), str(output_dir), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode >= 2 or not r.stdout:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Next Steps — conditional rules over the run's state
# ---------------------------------------------------------------------------


def build_next_steps(
    output_dir: Path,
    repo_root: Path,
    metrics: dict,
    cfg: dict,
) -> list[str]:
    """Apply the conditional rules from SKILL.md → "Next Steps block".

    Returns a capped 5-item list (most actionable first). Always-lines 1
    and 2 take priority, then architect-review, then SARIF, then
    requirements, then reasoning-model hint, then dep-scan, then baseline.
    """
    lines: list[str] = []
    sev = metrics["threats_by_sev"]
    critical = sev.get("Critical", 0)
    high = sev.get("High", 0)

    # Always line 1.
    lines.append(f'Open {output_dir}/threat-model.md → "Management Summary" for verdict + top risks')
    # Always line 2 (if any Critical/High).
    if critical or high:
        top = "Critical" if critical else "High"
        lines.append(f'Review {top} findings in Section 8 "Findings Register"')

    # Architect review — only surface the dot-file when it contains actionable defects.
    # Advisory-only reviews (technical_defects=0, no repair plan) are internal
    # artefacts; everything important is already in threat-model.md.
    if cfg.get("architect_review") and (output_dir / ".architect-review.md").is_file():
        _arch_status_path = output_dir / ".architect-status.json"
        _arch_has_defects = True  # default: show it if we can't read the status
        if _arch_status_path.is_file():
            try:
                _arch_data = json.loads(_arch_status_path.read_text(encoding="utf-8"))
                _arch_has_defects = int(_arch_data.get("technical_defects", 1)) > 0 or bool(
                    _arch_data.get("repair_plan_exists", False)
                )
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                pass
        if _arch_has_defects:
            lines.append(f"Review {output_dir}/.architect-review.md → architect-level verdict and findings")

    # SARIF uploaded.
    if cfg.get("write_sarif") and (output_dir / "threat-model.sarif.json").is_file():
        lines.append("Upload threat-model.sarif.json to GitHub Advanced Security / SonarQube / DefectDojo")

    # Requirements not checked.
    if not cfg.get("check_requirements"):
        lines.append("Re-run with --requirements to verify SEC-* baseline compliance")

    # Sonnet-only run with significant Critical/High.
    if cfg.get("reasoning_model") == "sonnet" and (critical + high) >= 3:
        lines.append(
            "Re-run with --reasoning-model opus for deeper STRIDE analysis (~5× cost, typically +15-25% finding depth)"
        )

    # First-run baseline established.
    if not (output_dir / ".appsec-cache" / "baseline.json").is_file() and cfg.get("mode") == "full":
        lines.append("Future runs will auto-detect this baseline and switch to incremental mode (faster, cheaper)")

    # Cap at 5.
    return lines[:5]


def _has_dependency_manifest(repo_root: Path) -> bool:
    for name in (
        "package.json",
        "requirements.txt",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
        "pyproject.toml",
        "composer.json",
    ):
        if (repo_root / name).is_file():
            return True
    return False


# ---------------------------------------------------------------------------
# Rendering — assemble the final summary text
# ---------------------------------------------------------------------------


def render_change_summary(cs: dict) -> list[str]:
    lines = [""]
    lines.append("Change Summary")
    lines.append(f"  Prior baseline: {cs['cl_mode']} run from {cs['date']}, commit {cs['baseline_short']}")
    lines.append(f"  Added      : {cs['added_n']} threats")
    lines.append(f"  Changed    : {cs['changed_n']} threats")
    lines.append(f"  Resolved   : {cs['resolved_n']} threats")
    if cs.get("changed_files") is not None:
        lines.append(f"  Files      : {cs['changed_files']} security-relevant files changed")

    components_line = f"  Components : {cs['reanalyzed_n']} re-analyzed"
    if cs["cl_mode"] == "incremental":
        components_line += f", {cs['carried_n']} carried forward"
    lines.append(components_line)
    # Iterative runs list the actual finding IDs (no titles) — new ones and,
    # where identifiable, removed ones — and say so explicitly even when the
    # delta is empty, so an unchanged re-scan is never silent.
    if cs.get("is_iterative"):
        new_ids = cs.get("added_id_list") or []
        gone_ids = cs.get("resolved_id_list") or []
        lines.append(f"  New IDs    : {', '.join(new_ids) if new_ids else 'none'}")
        lines.append(f"  Removed IDs: {', '.join(gone_ids) if gone_ids else 'none'}")
        if not new_ids and not gone_ids:
            lines.append("  (no new or resolved findings since the baseline)")
    lines.append(f"  Changelog : v{cs['version']} prepended to threat-model.md")
    return lines


def render_threat_delta(cs: Optional[dict]) -> list[str]:
    if not cs:
        return []
    groups = [
        ("New", cs.get("added_entries") or [], cs.get("added_more") or 0),
        ("Resolved", cs.get("resolved_entries") or [], cs.get("resolved_more") or 0),
        ("Changed", cs.get("changed_entries") or [], cs.get("changed_more") or 0),
    ]
    if not any(entries for _, entries, _ in groups):
        return []

    lines = ["", "Threat Delta"]
    for label, entries, more in groups:
        if not entries:
            continue
        lines.append(f"  {label}")
        for entry in entries:
            lines.append(f"    {entry}")
        if more:
            lines.append(f"    ... +{more} more")
        lines.append("")
    if lines[-1] == "":
        lines.pop()
    return lines


def render_metrics(metrics: dict, cfg: dict) -> list[str]:
    lines = [""]
    lines.append("Results")
    s = metrics["threats_by_sev"]
    lines.append(
        f"  Threats    : {metrics['threats_total']} total | "
        f"{s['Critical']} Critical | {s['High']} High | "
        f"{s['Medium']} Medium | {s['Low']} Low"
    )
    lines.append(f"  Components : {metrics['n_components']} analyzed")
    cs = metrics["control_status"]
    # RC.F — render all 5 effectiveness buckets per sections-contract.yaml
    # `effectiveness_taxonomy` (adequate/partial/weak/unsafe/missing). Earlier
    # this line dropped buckets (first `weak`, later `unsafe`) so the breakdown
    # total did not reconcile with `{controls_total} cataloged` (2026-05: 12
    # cataloged rendered 0/3/6=9; 2026-06 juice-shop: 38 cataloged rendered
    # 3/7/2/23=35, dropping 3 Unsafe).
    lines.append(
        f"  Controls   : {metrics['controls_total']} cataloged | "
        f"{cs['adequate']} adequate | {cs['partial']} partial | "
        f"{cs['weak']} weak | {cs['unsafe']} unsafe | {cs['missing']} missing"
    )
    lines.append(f"  Mitigations: {metrics['mitigations_total']} linked")
    if cfg.get("check_requirements"):
        r = metrics["requirements"]
        lines.append(
            f"  Requirements: {r['total']} checked | {r['pass']} pass | {r['fail']} fail | {r['partial']} partial"
        )
    return lines


_PHASE_DESCRIPTIONS = {
    "1": "Context Resolution",
    "2": "Reconnaissance",
    "3": "Architecture Modeling",
    "4": "Attack Walkthroughs",
    "5": "Asset Identification",
    "6": "Attack Surface Mapping",
    "7": "Trust Boundary Analysis",
    "8": "Security Controls Catalog",
    "9": "STRIDE Enumeration",
    "10": "Scan Synthesis",
    "10b": "Triage Validation",
    "11": "Finalization",
}

_PHASE_AGENT = {
    "1": "threat-analyst",
    "2": "recon-scanner",
    "3": "threat-analyst",
    "4": "threat-analyst",
    "5": "threat-analyst",
    "6": "threat-analyst",
    "7": "threat-analyst",
    "8": "threat-analyst",
    "9": "stride-analyzer",
    "10": "threat-analyst",
    "10b": "triage-validator",
    "11": "threat-analyst",
}


def render_run_statistics(stats: dict, cost: Optional[dict], verbose: bool = False) -> list[str]:
    # Total duration header — net agent compute vs. end-to-end wall, with
    # machine standby/suspend explicitly isolated (run_timing.py). A run that
    # sat in standby otherwise reports a wall-clock dominated by sleep plus a
    # confusing unexplained gap; breaking standby out makes the NET time the
    # user actually spent unambiguous.
    timing = stats.get("timing") or {}
    net_compute = timing.get("net_compute_secs") or 0
    wall = timing.get("wall_secs") or stats.get("wall_secs") or 0
    standby = timing.get("standby_secs") or 0

    if stats["assess_secs"] is None and not stats["phases"] and not stats["stage_rows"] and not wall:
        # Nothing to render — skip the whole block rather than printing zeroes
        # and placeholders. A known wall-clock alone (`.stage-stats.jsonl`
        # absent but `.scan-wall-seconds` written) is enough to keep the block:
        # the end-to-end duration must still surface (regression 2026-06-14).
        return []
    lines = [""]
    lines.append(f"  -- Run Statistics {SECTION_RULE[:42]}")

    # Legacy assess+qa+arch sum — fallback only for pre-stage-stats runs
    # (no .stage-stats.jsonl, so net_compute is 0).
    legacy_total = 0
    legacy_parts = []
    if stats["assess_secs"] is not None:
        legacy_parts.append(f"assessment: {_fmt_duration(stats['assess_secs'])}")
        legacy_total += stats["assess_secs"]
    if stats["qa_secs"]:
        legacy_parts.append(f"QA review: {_fmt_duration(stats['qa_secs'])}")
        legacy_total += stats["qa_secs"]
    if stats["arch_secs"]:
        legacy_parts.append(f"architect review: {_fmt_duration(stats['arch_secs'])}")
        legacy_total += stats["arch_secs"]

    # Net = agent compute from .stage-stats.jsonl. The legacy assess+qa+arch
    # sum is used ONLY when no stage stats exist (so the two paths never both
    # print). Stage-data path shows the full Net / Idle / Wall breakdown;
    # legacy path shows a single total line.
    net = net_compute or stats.get("total_secs_from_stages") or 0
    if net:
        lines.append(f"  Net agent compute   : {_fmt_duration(net)}  (sum of per-stage agent time)")

        # Idle / standby breakdown — only when a wall-clock is available to
        # compare against the net compute.
        if wall and wall > net:
            idle_total = wall - net
            lines.append(f"  Idle / standby      : {_fmt_duration(idle_total)}  (excluded from net compute)")
            # The standby/suspend vs API+orchestration split is extra detail —
            # verbose-only. The default summary keeps a single Idle line.
            if verbose and standby > 0:
                lines.append(
                    f"     standby/suspend  : {_fmt_duration(standby)}  (>10m gap — machine asleep or hung dispatch)"
                )
                lines.append(f"     API + orchestr.  : {_fmt_duration(max(0, idle_total - standby))}")

    # End-to-end wall-clock — surfaced whenever it is known, INDEPENDENT of
    # whether per-stage agent compute is available. When `.stage-stats.jsonl`
    # is absent (net == 0) this is the only duration figure, so it must not be
    # gated behind the net-compute branch — doing so dropped the duration from
    # the console summary entirely (regression 2026-06-14).
    if wall and wall > 0:
        if standby > 0:
            # Make explicit that the headline wall includes dead standby
            # time, and surface the standby-corrected figure the estimator
            # uses as the next-run basis.
            # The standby-corrected "Net run" figure is verbose-only detail;
            # the default keeps just the raw end-to-end wall (which still
            # notes the standby it includes).
            if verbose:
                net_wall = timing.get("net_wall_secs") or (wall - standby)
                lines.append(
                    f"  Net run (wall−sleep): {_fmt_duration(net_wall)}  "
                    f"(standby excluded — basis for the next estimate)"
                )
            lines.append(
                f"  Total elapsed (wall): {_fmt_duration(wall)}  (end-to-end, incl. {_fmt_duration(standby)} standby)"
            )
        else:
            lines.append(f"  Total elapsed (wall): {_fmt_duration(wall)}  (end-to-end, incl. orchestration)")
    elif not net and legacy_total:
        # Pre-stage-stats run with no wall-clock: no `.stage-stats.jsonl` and no
        # `.scan-wall-seconds`. Fall back to the legacy assess+qa+arch sum so
        # the block is not empty.
        suffix = f"  ({' + '.join(legacy_parts)})" if legacy_parts else ""
        lines.append(f"  Total (legacy)      : {_fmt_duration(legacy_total)}{suffix}")

    # Everything below — the per-stage duration breakdown, the agent roster, and
    # the token/cost block — is verbose-only. The default summary stops at the
    # timing headline (net compute / idle / wall); `--verbose` adds the detail.
    if not verbose:
        return lines

    # Per-stage breakdown.
    # Sourced from ``.stage-stats.jsonl`` (one record per Stage agent dispatch,
    # written by ``record_stage_stats.py``). This is the authoritative timing
    # source — it captures every dispatch including Stage 2 renderer and Stage 3
    # repair iterations, and is robust to the parallel-STRIDE path where the
    # ``.agent-run.log`` PHASE markers get overwritten or skipped. Replaces the
    # older log-derived per-phase block, which rendered ``(inline)`` for most
    # rows in the default parallel run.
    stage_rows = sorted(
        stats["stage_rows"],
        key=lambda r: (r[0] if isinstance(r[0], (int, float)) else 99, r[1]),
    )
    stage_nums_present = {r[0] for r in stage_rows}
    # Idle/standby annotation per row, keyed by (stage, variant). The per-row
    # figure is agent COMPUTE (duration_ms); when its wall window also held a
    # standby/suspend gap, flag it so the user sees WHERE the dead time was.
    idle_by_key = {(s.get("stage"), s.get("variant") or ""): s for s in timing.get("stages") or []}
    for stage, variant, name, agent, model, secs in stage_rows:
        # ``abuse-verification`` is the Stage-1 sub-step rendered as "1c"
        # everywhere else (TUI row, report table). Repair variants keep the
        # numeric stage and surface the variant in the description.
        label = "1c" if variant == "abuse-verification" else str(stage if stage is not None else "—")
        desc = name or f"Stage {stage}"
        if variant and variant != "abuse-verification":
            desc = f"{desc} ({variant})"
        duration = _fmt_duration(secs) if secs > 0 else "(n/a)"
        stage_tag = f"Stage {label}".ljust(10)
        desc_col = desc.ljust(28)[:28]
        agent_col = f"{agent} ({model})".ljust(32)
        tinfo = idle_by_key.get((stage, variant or ""))
        standby_note = ""
        if tinfo and tinfo.get("is_standby") and tinfo.get("idle_secs"):
            standby_note = f"   ⏸ +{_fmt_duration(tinfo['idle_secs'])} standby"
        lines.append(f"    {stage_tag}{desc_col}{agent_col}: {duration:>8}{standby_note}")

    # QA review is not a recorded stage (no .stage-stats.jsonl row) — surface it
    # from the log-derived qa_secs when present.
    if stats["qa_secs"]:
        agent_col = f"qa-reviewer ({stats['agents'].get('qa-reviewer', '?')})".ljust(32)
        lines.append(f"    {'QA':<10}{'QA Review'.ljust(26)}{agent_col}: {_fmt_duration(stats['qa_secs']):>8}")
    # Architect review is recorded as Stage 4 in the jsonl — only fall back to
    # the log-derived arch_secs row when no Stage 4 record exists (older runs).
    if stats["arch_secs"] and 4 not in stage_nums_present:
        model = stats["agents"].get("architect-reviewer", "?")
        agent_col = f"architect-reviewer ({model})".ljust(32)
        lines.append(
            f"    {'ARCH':<10}{'Architect Review'.ljust(26)}{agent_col}: {_fmt_duration(stats['arch_secs']):>8}"
        )

    # Agents summary line.
    if stats["agents"]:
        pairs = [f"{a}={m}" for a, m in sorted(stats["agents"].items())]
        lines.append(f"  Agents              : {', '.join(pairs)}")

    # Tokens & cost — delegated to verify_run_costs.
    if cost and "error" not in cost:
        totals = cost.get("totals") or {}
        billing = cost.get("billing") or "unknown"

        # Fix #5 — verify_run_costs.py emits `in`, `out`, `total_tokens`
        # (not `input`, `output`, `throughput`). The historical key-mismatch
        # rendered every Tokens line as "0 total (in: 0, out: 0, cache_write:
        # 4,386, cache_read: 520,827)" even when in/out were populated, and
        # then computed "Cache savings: 85.2%" on top of a Tokens=0 total —
        # mathematically meaningless. Use the canonical keys, with safe
        # fallback to the legacy names so older callers that still set
        # `throughput`/`input`/`output` keep working.
        total_tokens = totals.get("total_tokens") or totals.get("throughput") or 0
        tokens_in = totals.get("in") if "in" in totals else totals.get("input", 0)
        tokens_out = totals.get("out") if "out" in totals else totals.get("output", 0)
        cache_write = totals.get("cache_write", 0)
        cache_read = totals.get("cache_read", 0)
        if (total_tokens or 0) <= 0 and not cache_write and not cache_read and totals.get("cost", 0) <= 0:
            # Hook log captured no token data for the orchestrator session
            # (rare — usually means SESSION_STOP fired without a usage block).
            lines.append("  Tokens / Cost       : not captured by Claude Code hooks")
            lines.append("                        Run /usage in the chat for the actual figure.")
        else:
            # Hook data is available — render the measured numbers verbatim.
            lines.append(
                f"  Tokens              : {total_tokens:,} total "
                f"(in: {tokens_in:,}, "
                f"out: {tokens_out:,}, "
                f"cache_write: {cache_write:,}, "
                f"cache_read: {cache_read:,})"
            )
            savings = totals.get("cache_savings_pct")
            if billing == "subscription":
                # Subscription users don't pay per-run — suppress the dollar
                # estimates entirely. Keep tokens (factual) and cache savings
                # (factual) so observability is preserved.
                if savings is not None:
                    lines.append(f"  Cache savings       : {savings:.1f}%")
                lines.append("  Billing             : subscription (no per-run cost)")
            else:
                lines.append("  Cost (measured)     :")
                mix = cost.get("mixed_model_costs") or {}
                if mix:
                    for model, entry in mix.items():
                        lines.append(
                            f"    {model:<15} rates   : "
                            f"${entry.get('cached', 0):.4f} cached / "
                            f"${entry.get('no_cache', 0):.4f} no cache"
                        )
                else:
                    lines.append(f"    cost              : ${totals.get('cost', 0):.4f}")
                if savings is not None:
                    lines.append(f"    Cache savings     : {savings:.1f}%")
                lines.append(f"    Billing           : {billing}")
                lines.append("    Note              : measured from orchestrator hook stream; for the authoritative")
                lines.append("                        per-run figure, run /usage in the chat.")
    elif cost is None:
        lines.append("  Tokens/Cost         : unavailable (verify_run_costs.py failed)")
    return lines


def render_files(output_dir: Path, cfg: dict) -> list[str]:
    lines = ["", "Outputs"]
    lines.append(f"  Report     : {output_dir}/threat-model.md")
    if cfg.get("write_yaml", True):
        lines.append(f"  YAML       : {output_dir}/threat-model.yaml")
    sarif = output_dir / "threat-model.sarif.json"
    if cfg.get("write_sarif") and sarif.is_file():
        lines.append(f"  SARIF      : {sarif}")
    arch_md = output_dir / ".architect-review.md"
    if cfg.get("architect_review") and arch_md.is_file():
        lines.append(f"  Architect  : {arch_md} (advisory)")
    analysis_md = output_dir / "analysis-model.md"
    if analysis_md.is_file():
        lines.append(f"  Analysis   : {analysis_md} (architecture snapshot)")
    return lines


def extract_run_issues(output_dir: Path) -> Optional[dict]:
    """Read .run-issues.json (M2.15) and return a summary suitable for the
    `-- Run Issues --` block. Returns None on a clean run so the caller
    can skip the block entirely."""
    import json as _json

    path = output_dir / ".run-issues.json"
    if not path.is_file():
        return None
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("schema_version") != 1:
        return None
    if (data.get("run_status") or "").lower() == "clean" and not data.get("issues"):
        return None
    return data


def render_run_issues(data: Optional[dict], plugin_dev: bool = False) -> list[str]:
    """Render the conditional `-- Run Issues --` block. Returns empty list
    on clean runs so the caller can extend unconditionally.

    Fix suggestions (auto-applicable hints + /fix-run-issues call) are only
    shown when plugin_dev=True — they target plugin internals and are not
    actionable for end users.
    """
    if not data:
        return []
    summary = data.get("summary") or {}
    issues = data.get("issues") or []
    if not issues:
        return []

    lines: list[str] = []
    lines.append("  -- Run Issues ---------------------------------------------")
    n_err = summary.get("errors", 0)
    n_warn = summary.get("warnings", 0)
    n_perf = summary.get("perf_anomalies", 0)
    n_rec = summary.get("recovery_events", 0)
    n_auto = summary.get("auto_applicable_fixes", 0)
    bits = []
    if n_err:
        bits.append(f"{n_err} error{'s' if n_err != 1 else ''}")
    if n_warn:
        bits.append(f"{n_warn} warning{'s' if n_warn != 1 else ''}")
    if n_perf:
        bits.append(f"{n_perf} perf anomal{'ies' if n_perf != 1 else 'y'}")
    if n_rec:
        bits.append(f"{n_rec} recovery event{'s' if n_rec != 1 else ''}")
    summary_line = " · ".join(bits) if bits else "issues present"
    lines.append(f"  Status              : ⚠ {len(issues)} issue(s) ({summary_line})")

    # Top 2 issues — sorted by severity (errors first).
    sev_rank = {"error": 0, "warning": 1, "info": 2}
    sorted_issues = sorted(issues, key=lambda i: sev_rank.get(i.get("severity", "info"), 9))
    for issue in sorted_issues[:2]:
        title = issue.get("title", "(no title)")
        if len(title) > 78:
            title = title[:75] + "…"
        lines.append(f"  Top issue           : {title}")
        if plugin_dev:
            fr = issue.get("fix_recommendation") or {}
            if fr.get("auto_applicable"):
                lines.append(f"                        ↳ Auto-fix available: {fr.get('summary', '')[:70]}")
            else:
                lines.append(f"                        ↳ Manual review: {fr.get('category', '?')}")

    if len(issues) > 2:
        lines.append(f"                        ({len(issues) - 2} more — see .run-issues.json)")

    if plugin_dev and n_auto > 0:
        lines.append(f"  Auto-applicable     : {n_auto} of {len(issues)} fix(es) ready to apply")
        lines.append("  Apply fixes         : /appsec-advisor:fix-run-issues")

    lines.append("")
    return lines


def extract_composition_health(output_dir: Path) -> Optional[dict]:
    """Read .compose-stats.json + .inline-shortcut-retry-count and return a
    summary dict for the Composition Health block. Returns None when the
    pipeline ran cleanly so the caller can skip the section entirely.

    Schema:
        {
            "status": "warned",
            "warning_count": int,
            "warnings": [{section, category, detail}],
            "section_retries": {section_id: attempts},
            "auto_retries": int,
        }
    """
    import json as _json

    stats_path = output_dir / ".compose-stats.json"
    retry_path = output_dir / ".inline-shortcut-retry-count"

    stats = None
    if stats_path.is_file():
        try:
            stats = _json.loads(stats_path.read_text(encoding="utf-8"))
            if not isinstance(stats, dict):
                stats = None
            elif stats.get("schema_version") != 1:
                stats = None  # forward-incompatible
        except (OSError, ValueError):
            stats = None

    auto_retries = 0
    if retry_path.is_file():
        try:
            auto_retries = int(retry_path.read_text(encoding="utf-8").strip() or 0)
        except (OSError, ValueError):
            auto_retries = 0

    warnings = (stats or {}).get("warnings") or []
    section_retries = (stats or {}).get("section_retries") or {}
    is_clean = not warnings and not section_retries and auto_retries == 0
    if is_clean:
        return None

    return {
        "status": "warned",
        "warning_count": len(warnings),
        "warnings": warnings,
        "section_retries": section_retries,
        "auto_retries": auto_retries,
    }


def render_composition_health(health: Optional[dict]) -> list[str]:
    """Render the conditional Composition Health block. Returns an empty
    list when health is None (clean run) so the caller can extend
    unconditionally."""
    if not health:
        return []
    lines: list[str] = []
    lines.append("  -- Composition Health -------------------------------------")
    n_warn = health["warning_count"]
    n_retry = sum(health["section_retries"].values()) if health["section_retries"] else 0
    n_auto = health["auto_retries"]
    summary_bits: list[str] = []
    if n_warn:
        summary_bits.append(f"{n_warn} soft warning{'s' if n_warn != 1 else ''}")
    if health["section_retries"]:
        summary_bits.append(
            f"{len(health['section_retries'])} section{'s' if len(health['section_retries']) != 1 else ''} retried"
        )
    if n_auto:
        summary_bits.append(f"{n_auto} auto-retry cycle{'s' if n_auto != 1 else ''}")
    summary = ", ".join(summary_bits) or "issues present"
    lines.append(f"  Status              : ⚠ Warned ({summary})")

    if health["section_retries"]:
        retry_str = ", ".join(f"§{sid} ({n}/3)" for sid, n in sorted(health["section_retries"].items()))
        lines.append(f"  Section retries     : {retry_str}")

    if health["warnings"]:
        # Show up to 2 warnings inline; full list is in the §Composition
        # Notes appendix in threat-model.md.
        for w in health["warnings"][:2]:
            sec = w.get("section", "(unspecified)")
            det = w.get("detail", "")
            if len(det) > 90:
                det = det[:87] + "…"
            lines.append(f"  Soft warning        : {sec} — {det}")
        if len(health["warnings"]) > 2:
            lines.append(f"                        ({len(health['warnings']) - 2} more in §Composition Notes appendix)")

    if n_auto:
        lines.append(
            f"  Auto-retries        : {n_auto} inline-shortcut recovery cycle{'s' if n_auto != 1 else ''} (succeeded)"
        )

    lines.append("  See `## Appendix: Composition Notes` in threat-model.md for the full picture.")
    lines.append("")
    return lines


def render_next_steps(next_steps: list[str]) -> list[str]:
    if not next_steps:
        return []
    lines = [""]
    lines.append("Next Steps")
    for i, step in enumerate(next_steps, start=1):
        lines.append(f"  {i}. {step}")
    return lines


def render_security_notice(output_dir: Path) -> list[str]:
    """Emit a security notice when threat-model.md is not git-ignored.

    Checks whether docs/security/ (or the actual output_dir) is covered by
    .gitignore in the nearest git root.  If the file would be tracked, warn
    the user.  Silently skipped when git is unavailable or outside a repo.
    """
    try:
        import subprocess

        result = subprocess.run(
            ["git", "check-ignore", "-q", str(output_dir / "threat-model.md")],
            capture_output=True,
            cwd=str(output_dir),
        )
        if result.returncode == 0:
            # File is ignored — no notice needed.
            return []
    except Exception:
        return []

    lines = [""]
    lines.append("Security Notice")
    lines.append("  Warning: threat-model.md is NOT git-ignored and may be committed.")
    lines.append("  Threat reports contain sensitive vulnerability details,")
    lines.append("  attack vectors, and architecture weaknesses.")
    lines.append("  Add docs/security/ to .gitignore to keep them out of git.")
    lines.append("  To publish deliberately (private repo, policy permits it):")
    lines.append("    /appsec-advisor:publish-threat-model")
    lines.append("  The publish skill runs pre-flight checks and patches .gitignore.")
    return lines


def render_log_files(output_dir: Path) -> list[str]:
    lines = [""]
    lines.append("Logs")
    lines.append(f"  Agent run  : {output_dir}/.agent-run.log")
    lines.append(f"  Hook events: {output_dir}/.hook-events.log")
    qa_status = output_dir / ".qa-status.json"
    if qa_status.is_file():
        lines.append(f"  QA status  : {qa_status}")
    return lines


def _summary_duration(stats: dict) -> str:
    total = stats.get("total_secs_from_stages")
    if not total:
        total = sum(secs or 0 for secs in (stats.get("assess_secs"), stats.get("qa_secs"), stats.get("arch_secs")))
    if not total:
        # Last resort: the end-to-end wall-clock. When `.stage-stats.jsonl` is
        # absent there is no per-stage compute to sum, but the wall-clock marker
        # is still an honest "how long did it take" figure — far better than
        # showing n/a (regression 2026-06-14).
        timing = stats.get("timing") or {}
        total = timing.get("wall_secs") or stats.get("wall_secs") or 0
    return _fmt_duration(total) if total else "n/a"


def _summary_cost(cost: Optional[dict]) -> str:
    if not cost or "error" in cost:
        return "unavailable"
    totals = cost.get("totals") or {}
    billing = cost.get("billing") or "unknown"
    if billing == "subscription":
        return "subscription"
    value = totals.get("cost")
    if isinstance(value, (int, float)) and value > 0:
        return f"${value:.2f}"
    return "not captured"


def _summary_qa(output_dir: Path, cfg: dict) -> str:
    if cfg.get("skip_qa"):
        return "skipped"
    status_path = output_dir / ".qa-status.json"
    if not status_path.is_file():
        return "not recorded"
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "status unreadable"
    status = str(data.get("status") or "recorded")
    return status.replace("_", " ")


def _summary_architect(output_dir: Path, cfg: dict) -> str:
    if not cfg.get("architect_review"):
        return "skipped"
    status_path = output_dir / ".architect-status.json"
    if status_path.is_file():
        try:
            data = json.loads(status_path.read_text(encoding="utf-8"))
            return str(data.get("status") or "recorded").replace("_", " ")
        except (OSError, json.JSONDecodeError):
            return "status unreadable"
    if (output_dir / ".architect-review.md").is_file():
        return "completed"
    return "not recorded"


def render_run_overview(
    repo_root: Path,
    output_dir: Path,
    cfg: dict,
    stats: dict,
    cost: Optional[dict],
    change: Optional[dict],
) -> list[str]:
    mode = cfg.get("mode", "full")
    scope = "full repository assessment"
    if mode == "incremental":
        scope = "security-relevant delta from previous threat-model.yaml"
    elif mode == "rebuild":
        scope = "fresh full repository assessment"
    if change:
        mode = f"{mode} (delta: +{change['added_n']} / ~{change['changed_n']} / -{change['resolved_n']})"
    return [
        "Assessment complete: Create Threat Model",
        "",
        "Repository",
        f"  {repo_root}",
        "",
        "Run",
        f"  Mode      : {mode}",
        f"  Scope     : {scope}",
        f"  Depth     : {cfg.get('assessment_depth', 'standard')}",
        f"  Duration  : {_summary_duration(stats)}",
        f"  Cost      : {_summary_cost(cost)}",
        f"  QA        : {_summary_qa(output_dir, cfg)}",
        f"  Architect : {_summary_architect(output_dir, cfg)}",
    ]


def render_summary(
    output_dir: Path,
    repo_root: Path,
    cfg: dict,
    plugin_root: Path,
) -> str:
    yaml_data = _load_yaml(output_dir / "threat-model.yaml")
    md_text = _load_text(output_dir / "threat-model.md")
    metrics = extract_metrics(yaml_data, md_text)
    change = extract_change_summary(yaml_data)
    stats = extract_run_statistics(output_dir, yaml_data)
    cost = extract_costs(output_dir, plugin_root)
    next_steps = build_next_steps(output_dir, repo_root, metrics, cfg)

    lines: list[str] = []
    lines.extend(render_run_overview(repo_root, output_dir, cfg, stats, cost, change))
    lines.extend(render_metrics(metrics, cfg))

    if cfg.get("quiet"):
        # Compact console mode (--quiet): print only the essentials plus any
        # problem signals — Repository / Run / Results, run-issue + security
        # warnings (when present), and Outputs. Omit the verdict, change
        # summary / threat delta, composition health, next steps, run
        # statistics, and the log listing; the full detail stays in the report.
        run_issues = extract_run_issues(output_dir)
        lines.extend(render_run_issues(run_issues, plugin_dev=cfg.get("plugin_dev", False)))
        lines.extend(render_security_notice(output_dir))
        lines.extend(render_files(output_dir, cfg))
        return "\n".join(lines) + "\n"

    lines.extend(render_verdict(md_text, cfg))
    if change:
        lines.extend(render_change_summary(change))
        lines.extend(render_threat_delta(change))
    lines.extend(render_files(output_dir, cfg))
    # M2.14 — Sprint 6 observability. Conditional block: rendered only when
    # the prior compose run reported soft warnings, section retries, or the
    # skill-level auto-retry loop fired. On a clean run the section is
    # skipped entirely (no extra noise in the canonical output).
    health = extract_composition_health(output_dir)
    lines.extend(render_composition_health(health))
    # M2.15 — Sprint 7 observability. Conditional block: rendered only when
    # .run-issues.json reports issues. On a clean run the section is
    # omitted entirely (no extra noise).
    run_issues = extract_run_issues(output_dir)
    lines.extend(render_run_issues(run_issues, plugin_dev=cfg.get("plugin_dev", False)))
    lines.extend(render_next_steps(next_steps))
    lines.extend(render_security_notice(output_dir))
    lines.extend(render_run_statistics(stats, cost, verbose=cfg.get("verbose", False)))
    lines.extend(render_log_files(output_dir))

    return "\n".join(lines) + "\n"


def render_dry_run(output_dir: Path, repo_root: Path) -> str:
    yaml_data = _load_yaml(output_dir / "threat-model.yaml")
    md_text = _load_text(output_dir / "threat-model.md")
    metrics = extract_metrics(yaml_data, md_text)
    ms_block = _extract_management_summary(md_text)

    lines = [RULE, "  Dry-Run — Threat Model Preview", RULE, ""]
    lines.append(f"  Repository      : {repo_root}")
    lines.append(f"  Components      : {metrics['n_components']} analyzed")
    lines.append("")
    if ms_block:
        lines.append(ms_block)
    s = metrics["threats_by_sev"]
    cs = metrics["control_status"]
    lines.append("")
    lines.append(f"  -- Metrics {SECTION_RULE[:49]}")
    lines.append("")
    lines.append(
        f"  Threats         : {metrics['threats_total']} total "
        f"(Critical: {s['Critical']}, High: {s['High']}, "
        f"Medium: {s['Medium']}, Low: {s['Low']})"
    )
    lines.append(
        f"  Controls        : {metrics['controls_total']} cataloged "
        f"(adequate: {cs['adequate']}, partial: {cs['partial']}, "
        f"weak: {cs['weak']}, unsafe: {cs['unsafe']}, missing: {cs['missing']})"
    )
    lines.append("")
    lines.append("  Note: This is a preview. No files were written to the repository.")
    lines.append("  Run without --dry-run to generate the full threat model report.")
    lines.append(RULE)
    return "\n".join(lines) + "\n"


_MS_SLICE_RE = re.compile(
    r"^##\s+Management Summary\s*$\n(.+?)(?=\n##\s+[^\n]+\n|\Z)",
    re.DOTALL | re.MULTILINE,
)

# `### Verdict` is the first sub-section of `## Management Summary`. Slice it up
# to the next `### `/`## ` heading (typically `### Security Posture & Top
# Threats`) or end-of-document.
_VERDICT_SLICE_RE = re.compile(
    r"^###\s+Verdict\s*$\n(.+?)(?=\n#{2,3}\s+\S|\Z)",
    re.DOTALL | re.MULTILINE,
)


def _html_to_plain(body: str) -> str:
    """Strip the report's inline HTML so the slice reads cleanly on a console."""
    body = re.sub(r"<blockquote[^>]*>", "", body)
    body = re.sub(r"</blockquote>", "", body)
    body = re.sub(r"<br\s*/?>", "\n", body)
    body = re.sub(r'\sstyle="[^"]*"', "", body)
    return body.strip()


def _extract_management_summary(md_text: str) -> str:
    m = _MS_SLICE_RE.search(md_text)
    if not m:
        return ""
    return _html_to_plain(m.group(1))


def _extract_verdict(md_text: str) -> str:
    """Return the `### Verdict` sub-section as plain text (HTML stripped).

    Empty string when the section is absent (e.g. a malformed or partial
    report) — the caller then omits the console Verdict block entirely.
    """
    m = _VERDICT_SLICE_RE.search(md_text)
    if not m:
        return ""
    return _html_to_plain(m.group(1))


def render_verdict(md_text: str, cfg: dict) -> list[str]:
    """Console `-- Verdict --` block: the report's headline verdict.

    Shown by default so the user sees the assessment's bottom line without
    opening `threat-model.md`. Suppressed when `cfg["quiet"]` is set
    (the skill's `--quiet` flag).
    """
    if cfg.get("quiet"):
        return []
    verdict = _extract_verdict(md_text)
    if not verdict:
        return []
    lines = ["", f"  -- Verdict {SECTION_RULE[:48]}", ""]
    for ln in verdict.splitlines():
        lines.append(f"  {ln}" if ln.strip() else "")
    return lines


# ---------------------------------------------------------------------------
# Placeholder patching — patch _pending_ in the Run Statistics appendix
# ---------------------------------------------------------------------------


def patch_placeholders(output_dir: Path, stats: dict) -> int:
    """Replace ``_pending_`` markers in the Run Statistics appendix.

    Returns the number of substitutions made. Idempotent — a second call
    is a no-op because the markers are gone.
    """
    md_path = output_dir / "threat-model.md"
    if not md_path.is_file():
        return 0
    text = md_path.read_text(encoding="utf-8")

    patches = 0
    assess_dur = _fmt_duration(stats["assess_secs"]) if stats["assess_secs"] else "n/a"
    qa_dur = _fmt_duration(stats["qa_secs"]) if stats["qa_secs"] else "n/a"
    total_secs = (stats["assess_secs"] or 0) + (stats["qa_secs"] or 0)
    total_dur = _fmt_duration(total_secs) if total_secs else "n/a"
    qa_model = stats["agents"].get("qa-reviewer", "n/a")

    # Three specific placeholder rows + qa-reviewer pending model. Use
    # ``\g<N>`` syntax so a group reference followed by a literal digit
    # (e.g. `\g<1>4m 44s`) does not collide with the Python regex engine's
    # ``\NN`` back-reference parser.
    replacements = [
        (
            r"(\|\s*\*\*Assessment Total\*\*\s*\|\s*\|\s*\|\s*\*\*)_pending_(\*\*\s*\|)",
            rf"\g<1>{assess_dur}\g<2>",
        ),
        (
            r"(\|\s*QA Review\s*\|[^\|]*\|[^\|]*\|\s*)_pending_(\s*\|)",
            rf"\g<1>{qa_dur}\g<2>",
        ),
        (
            r"(\|\s*\*\*Grand Total\*\*\s*\|\s*\|\s*\|\s*\*\*)_pending_(\*\*\s*\|)",
            rf"\g<1>{total_dur}\g<2>",
        ),
        (
            r"(qa-reviewer\s*\|[^\|]*\|\s*)_pending_(\s*\|)",
            rf"\g<1>{qa_model}\g<2>",
        ),
    ]

    new_text = text
    for pat, repl in replacements:
        new_text, n = re.subn(pat, repl, new_text, flags=re.IGNORECASE)
        patches += n
    if new_text != text:
        md_path.write_text(new_text, encoding="utf-8")
    return patches


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _bool_pair(
    parser: argparse.ArgumentParser, name: str, dest: str, default: bool, help_on: str = "", help_off: str = ""
) -> None:
    """Register --foo / --no-foo as a mutually-exclusive boolean pair."""
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(f"--{name}", dest=dest, action="store_true", default=default, help=help_on)
    grp.add_argument(f"--no-{name}", dest=dest, action="store_false", help=help_off)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="render_completion_summary.py", description=__doc__.splitlines()[0])
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--repo-root", type=Path, required=True)
    p.add_argument("--mode", default="full", choices=("full", "incremental", "rebuild", "dry-run"))
    p.add_argument(
        "--reasoning-model",
        default="opus",
        choices=("opus-cheap", "sonnet", "opus", "sonnet-economy", "haiku-economy"),
    )
    p.add_argument("--assessment-depth", default="standard", choices=("quick", "standard", "thorough"))
    _bool_pair(p, "write-yaml", "write_yaml", True)
    _bool_pair(p, "write-sarif", "write_sarif", False)
    _bool_pair(p, "write-pentest-tasks", "write_pentest_tasks", False)
    _bool_pair(p, "check-requirements", "check_requirements", False)
    _bool_pair(p, "architect-review", "architect_review", False)
    p.add_argument(
        "--plugin-dev",
        action="store_true",
        help="Show fix suggestions in Run Issues block (plugin developer mode). Enable via APPSEC_PLUGIN_DEV=1.",
    )
    p.add_argument("--patch-placeholders", action="store_true")
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Add the per-stage duration breakdown, agent roster, and token/cost "
        "detail to the Run Statistics block. Default shows only the timing headline.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Compact console summary: print only the essentials — Repository, "
        "Run, Results, Outputs, plus any run-issue / security warnings. "
        "Omits the verdict, change summary, threat delta, next steps, run "
        "statistics, and the log listing (all still available in the report).",
    )
    p.add_argument(
        "--no-print",
        dest="no_print",
        action="store_true",
        help="Suppress the rendered completion summary on stdout. "
        "Useful when invoked solely to patch placeholders "
        "(e.g. from Stage 2 where the skill renders the final "
        "summary itself after Stage 3).",
    )
    p.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = p.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"error: output_dir not a directory: {args.output_dir}", file=sys.stderr)
        return 2

    cfg = {
        "mode": args.mode,
        "reasoning_model": args.reasoning_model,
        "assessment_depth": args.assessment_depth,
        "write_yaml": args.write_yaml,
        "write_sarif": args.write_sarif,
        "write_pentest_tasks": args.write_pentest_tasks,
        "check_requirements": args.check_requirements,
        "architect_review": args.architect_review,
        "plugin_dev": args.plugin_dev,
        "verbose": args.verbose,
        "quiet": args.quiet,
    }

    if args.mode == "dry-run":
        print(render_dry_run(args.output_dir, args.repo_root), end="")
        return 0

    md_path = args.output_dir / "threat-model.md"
    if not md_path.is_file():
        print(f"error: threat-model.md not found in {args.output_dir}", file=sys.stderr)
        return 2

    # Compute stats once; used for patching + rendering.
    yaml_data = _load_yaml(args.output_dir / "threat-model.yaml")
    stats = extract_run_statistics(args.output_dir, yaml_data)

    if args.patch_placeholders:
        patch_placeholders(args.output_dir, stats)

    if not args.no_print:
        print(render_summary(args.output_dir, args.repo_root, cfg, args.plugin_root), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
