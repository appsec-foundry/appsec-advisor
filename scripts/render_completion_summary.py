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
    --with-sca / --no-with-sca
    --reasoning-model {opus-cheap,sonnet,opus,haiku-economy}
                                Used only to decide whether the "re-run
                                with --reasoning-model opus" Next Steps
                                line should appear (Sonnet-only runs).
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
    control_status = {"adequate": 0, "partial": 0, "weak": 0, "missing": 0}
    for c in controls:
        eff = (c.get("effectiveness") or c.get("status") or "").strip().lower()
        if eff in control_status:
            control_status[eff] += 1

    # Requirements compliance — present only when the skill ran with
    # --requirements. Not in this run; we still expose the field so the
    # renderer can decide.
    req = yaml_data.get("requirements_compliance") or {}
    req_counts = {
        "pass":    req.get("pass")    or 0,
        "fail":    req.get("fail")    or 0,
        "partial": req.get("partial") or 0,
        "total":   req.get("total")   or 0,
    }

    return {
        "threats_total":  len(threats),
        "threats_by_sev": by_sev,
        "n_components":   n_components,
        "controls_total": len(controls),
        "control_status": control_status,
        "requirements":   req_counts,
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


def extract_change_summary(yaml_data: dict) -> Optional[dict]:
    """Returns None when no baseline / first-run, else a dict ready to
    feed into ``render_change_summary``."""
    cl = yaml_data.get("changelog") or []
    if not cl:
        return None
    e = cl[0]
    if not isinstance(e, dict):
        return None
    added_ids    = ((e.get("added")    or {}).get("threats") or [])
    changed_ids  = ((e.get("changed")  or {}).get("threats") or [])
    resolved_ids = ((e.get("resolved") or {}).get("threats") or [])

    # Only render when the entry has delta data. First-run full assessments
    # produce a changelog[0] but with empty deltas — skip those.
    has_delta = bool(added_ids or changed_ids or resolved_ids)
    if not has_delta and not (
        e.get("reanalyzed_components") or e.get("carried_forward_components")
    ):
        return None

    notes_by_id   = ((e.get("changed")  or {}).get("notes_by_id")  or {})
    reasons_by_id = ((e.get("resolved") or {}).get("reason_by_id") or {})

    changed_fmt  = lambda i: (
        f"{i} ({notes_by_id[i]})" if i in notes_by_id else i
    )
    resolved_fmt = lambda i: (
        f"{i} ({reasons_by_id[i]})" if i in reasons_by_id else i
    )

    baseline_sha = e.get("baseline_sha") or "n/a"
    return {
        "added_n":        len(added_ids),
        "changed_n":      len(changed_ids),
        "resolved_n":     len(resolved_ids),
        "added_ids":      _sample_ids(added_ids),
        "changed_ids":    _sample_ids(changed_ids, changed_fmt),
        "resolved_ids":   _sample_ids(resolved_ids, resolved_fmt),
        "reanalyzed_n":   len(e.get("reanalyzed_components") or []),
        "carried_n":      len(e.get("carried_forward_components") or []),
        "cl_mode":        e.get("mode", "?"),
        "baseline_short": baseline_sha[:12] if baseline_sha != "n/a" else "n/a",
        "version":        e.get("version", "?"),
        "date":           e.get("date", "?"),
    }


# ---------------------------------------------------------------------------
# Run statistics — durations + per-phase timeline from .agent-run.log
# ---------------------------------------------------------------------------


_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
_PHASE_START_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?PHASE_START\s+\[Phase\s+"
    r"(\d+[a-z]?)/\d+\]\s+[▶]*\s*(.+?)(?:\s*[…\(]|$)"
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
    "sonnet":         "sonnet-4-6",
    "opus":           "opus-4-7",
    "haiku":          "haiku-4-5",
    "claude-sonnet-4-6": "sonnet-4-6",
    "claude-opus-4-7":   "opus-4-7",
    "claude-haiku-4-5":  "haiku-4-5",
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


def _iso_to_epoch(ts: str) -> int:
    try:
        return int(_dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                   .replace(tzinfo=_dt.timezone.utc).timestamp())
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
    """
    log_path = output_dir / ".agent-run.log"
    log_text = _load_text(log_path)

    stats: dict[str, Any] = {
        "assess_secs": None,
        "qa_secs":     None,
        "arch_secs":   None,
        "phases":      [],
        "agents":      {},
    }

    meta = yaml_data.get("meta") or {}
    assess_secs = meta.get("analysis_duration_seconds")
    if isinstance(assess_secs, int) and assess_secs > 0:
        stats["assess_secs"] = assess_secs
    elif log_text:
        m = re.search(
            r"ASSESSMENT_END.*?completed in (\d+)\s*min\s*(\d+)\s*s", log_text
        )
        if m:
            stats["assess_secs"] = int(m.group(1)) * 60 + int(m.group(2))
        else:
            # Orchestrator was interrupted before ASSESSMENT_END. Use the
            # span from ASSESSMENT_START to the last PHASE_END (or last
            # PHASE_START when no PHASE_END was logged) as an approximation.
            start_m = re.search(
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*?ASSESSMENT_START",
                log_text,
            )
            last_phase_m = None
            for mm in re.finditer(
                r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*?PHASE_(?:END|START)",
                log_text,
            ):
                last_phase_m = mm
            if start_m and last_phase_m:
                start_ep = _iso_to_epoch(start_m.group(1))
                end_ep   = _iso_to_epoch(last_phase_m.group(1))
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
    qa_end_ms = list(re.finditer(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?qa-reviewer\s+"
        r"(?:AGENT_COMPLETE|CHECK_END)", log_text,
    ))
    if qa_start_m and qa_end_ms:
        qa_start = _iso_to_epoch(qa_start_m.group(1))
        qa_end   = _iso_to_epoch(qa_end_ms[-1].group(1))
        if qa_start and qa_end >= qa_start:
            stats["qa_secs"] = qa_end - qa_start

    # Architect duration likewise.
    arch_start_m = re.search(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?architect-reviewer\s+AGENT_START",
        log_text,
    )
    arch_end_ms = list(re.finditer(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?architect-reviewer\s+"
        r"(?:AGENT_COMPLETE|CHECK_END)", log_text,
    ))
    if arch_start_m and arch_end_ms:
        a_start = _iso_to_epoch(arch_start_m.group(1))
        a_end   = _iso_to_epoch(arch_end_ms[-1].group(1))
        if a_start and a_end >= a_start:
            stats["arch_secs"] = a_end - a_start

    # Per-phase timeline.  Pair PHASE_START with the next PHASE_END for the
    # same phase-id; ignore overlapping "inline" entries where start and end
    # share the same timestamp.
    starts: dict[str, tuple[int, str]] = {}  # phase_id -> (epoch, description)
    phase_durations: list[tuple[str, str, int]] = []
    for line in log_text.splitlines():
        m = _PHASE_START_RE.search(line)
        if m:
            starts[m.group(2)] = (_iso_to_epoch(m.group(1)), m.group(3).strip())
            continue
        m = _PHASE_END_RE.search(line)
        if m:
            phase_id = m.group(2)
            end_ep = _iso_to_epoch(m.group(1))
            start_info = starts.get(phase_id)
            if start_info:
                start_ep, desc = start_info
                phase_durations.append((phase_id, desc, end_ep - start_ep))
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
    return stats


# ---------------------------------------------------------------------------
# Token & cost — delegate to verify_run_costs.py
# ---------------------------------------------------------------------------


def extract_costs(output_dir: Path, plugin_root: Path) -> Optional[dict]:
    """Return the parsed JSON from verify_run_costs.py, or None on failure."""
    script = plugin_root / "scripts" / "verify_run_costs.py"
    if not script.is_file():
        return None
    try:
        r = subprocess.run(
            ["python3", str(script), str(output_dir), "--json"],
            capture_output=True, text=True, timeout=30,
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
    high     = sev.get("High", 0)

    # Always line 1.
    lines.append(
        f'Open {output_dir}/threat-model.md → "Management Summary" '
        "for verdict + top risks"
    )
    # Always line 2 (if any Critical/High).
    if critical or high:
        top = "Critical" if critical else "High"
        lines.append(f'Review {top} findings in Section 8 "Threat Register"')

    # Architect review available.
    if cfg.get("architect_review") and (output_dir / ".architect-review.md").is_file():
        lines.append(
            f"Review {output_dir}/.architect-review.md → "
            "architect-level verdict and findings"
        )

    # SARIF uploaded.
    if cfg.get("write_sarif") and (output_dir / "threat-model.sarif.json").is_file():
        lines.append(
            "Upload threat-model.sarif.json to GitHub Advanced Security "
            "/ SonarQube / DefectDojo"
        )

    # Requirements not checked.
    if not cfg.get("check_requirements"):
        lines.append(
            "Re-run with --requirements to verify SEC-* baseline compliance"
        )

    # Sonnet-only run with significant Critical/High.
    if cfg.get("reasoning_model") == "sonnet" and (critical + high) >= 3:
        lines.append(
            "Re-run with --reasoning-model opus for deeper STRIDE analysis "
            "(~5× cost, typically +15-25% finding depth)"
        )

    # dep-scan was skipped and a manifest exists.
    if not cfg.get("with_sca") and _has_dependency_manifest(repo_root):
        lines.append(
            "Re-run with --with-sca to include CVE data from "
            "dependency advisories"
        )

    # First-run baseline established.
    if not (output_dir / ".appsec-cache" / "baseline.json").is_file() \
            and cfg.get("mode") == "full":
        lines.append(
            "Future runs will auto-detect this baseline and switch to "
            "incremental mode (faster, cheaper)"
        )

    # Cap at 5.
    return lines[:5]


def _has_dependency_manifest(repo_root: Path) -> bool:
    for name in (
        "package.json", "requirements.txt", "go.mod", "Cargo.toml",
        "pom.xml", "build.gradle", "pyproject.toml", "composer.json",
    ):
        if (repo_root / name).is_file():
            return True
    return False


# ---------------------------------------------------------------------------
# Rendering — assemble the final summary text
# ---------------------------------------------------------------------------


def render_change_summary(cs: dict) -> list[str]:
    lines = [""]
    lines.append(f"  -- Change Summary (vs. prior run) {SECTION_RULE[:28]}")
    lines.append(
        f"    Prior baseline     : {cs['cl_mode']} run from "
        f"{cs['date']}, commit {cs['baseline_short']}"
    )

    def fmt_delta(sym: str, label: str, n: int, ids: str) -> str:
        pad_label = f"{sym} {label}".ljust(18)
        ids_suffix = f"  ({ids})" if n > 0 and ids else ""
        return f"    {pad_label} : {n} threats{ids_suffix}"

    lines.append(fmt_delta("+", "Added",    cs["added_n"],    cs["added_ids"]))
    lines.append(fmt_delta("~", "Changed",  cs["changed_n"],  cs["changed_ids"]))
    lines.append(fmt_delta("-", "Resolved", cs["resolved_n"], cs["resolved_ids"]))

    components_line = f"    Components         : {cs['reanalyzed_n']} re-analyzed"
    if cs["cl_mode"] == "incremental":
        components_line += f", {cs['carried_n']} carried forward"
    lines.append(components_line)
    lines.append(
        f"    Changelog entry    : v{cs['version']} prepended to "
        "threat-model.md"
    )
    return lines


def render_metrics(metrics: dict, cfg: dict) -> list[str]:
    lines = [""]
    lines.append(f"  -- Metrics {SECTION_RULE[:49]}")
    s = metrics["threats_by_sev"]
    lines.append(
        f"  Threats             : {metrics['threats_total']} total "
        f"(Critical: {s['Critical']}, High: {s['High']}, "
        f"Medium: {s['Medium']}, Low: {s['Low']})"
    )
    lines.append(f"  Components          : {metrics['n_components']} analyzed")
    cs = metrics["control_status"]
    lines.append(
        f"  Controls            : {metrics['controls_total']} cataloged "
        f"(adequate: {cs['adequate']}, partial: {cs['partial']}, "
        f"missing: {cs['missing']})"
    )
    if cfg.get("check_requirements"):
        r = metrics["requirements"]
        lines.append(
            f"  Requirements        : {r['total']} checked "
            f"(pass: {r['pass']}, fail: {r['fail']}, partial: {r['partial']})"
        )
    return lines


_PHASE_DESCRIPTIONS = {
    "1":   "Context Resolution",
    "2":   "Reconnaissance",
    "3":   "Architecture Modeling",
    "4":   "Attack Walkthroughs",
    "5":   "Asset Identification",
    "6":   "Attack Surface Mapping",
    "7":   "Trust Boundary Analysis",
    "8":   "Security Controls Catalog",
    "9":   "STRIDE Enumeration",
    "10":  "Scan Synthesis",
    "10b": "Triage Validation",
    "11":  "Finalization",
}

_PHASE_AGENT = {
    "1":  "threat-analyst",
    "2":  "recon-scanner",
    "3":  "threat-analyst",
    "4":  "threat-analyst",
    "5":  "threat-analyst",
    "6":  "threat-analyst",
    "7":  "threat-analyst",
    "8":  "threat-analyst",
    "9":  "stride-analyzer",
    "10": "threat-analyst",
    "10b":"triage-validator",
    "11": "threat-analyst",
}


def render_run_statistics(stats: dict, cost: Optional[dict]) -> list[str]:
    if stats["assess_secs"] is None and not stats["phases"]:
        # Nothing to render — skip the whole block rather than
        # printing zeroes and placeholders.
        return []
    lines = [""]
    lines.append(f"  -- Run Statistics {SECTION_RULE[:42]}")

    # Total duration header.
    parts = []
    total = 0
    if stats["assess_secs"] is not None:
        parts.append(f"assessment: {_fmt_duration(stats['assess_secs'])}")
        total += stats["assess_secs"]
    if stats["qa_secs"]:
        parts.append(f"QA review: {_fmt_duration(stats['qa_secs'])}")
        total += stats["qa_secs"]
    if stats["arch_secs"]:
        parts.append(f"architect review: {_fmt_duration(stats['arch_secs'])}")
        total += stats["arch_secs"]
    if total:
        suffix = f"  ({' + '.join(parts)})" if parts else ""
        lines.append(f"  Total Duration      : {_fmt_duration(total)}{suffix}")

    # Per-phase breakdown.
    for phase_id, _desc, secs in stats["phases"]:
        desc = _PHASE_DESCRIPTIONS.get(phase_id, f"Phase {phase_id}")
        agent_name = _PHASE_AGENT.get(phase_id, "threat-analyst")
        model = stats["agents"].get(agent_name, "?")
        duration = _fmt_duration(secs) if secs > 0 else "(inline)"
        # Format: "    Phase N   <desc>  <agent (model)>  : <dur>"
        phase_tag = f"Phase {phase_id}".ljust(10)
        desc_col  = desc.ljust(26)
        agent_col = f"{agent_name} ({model})".ljust(32)
        lines.append(f"    {phase_tag}{desc_col}{agent_col}: {duration:>8}")

    if stats["qa_secs"]:
        agent_col = f"qa-reviewer ({stats['agents'].get('qa-reviewer', '?')})".ljust(32)
        lines.append(
            f"    {'QA':<10}{'QA Review'.ljust(26)}{agent_col}"
            f": {_fmt_duration(stats['qa_secs']):>8}"
        )
    if stats["arch_secs"]:
        model = stats["agents"].get("architect-reviewer", "?")
        agent_col = f"architect-reviewer ({model})".ljust(32)
        lines.append(
            f"    {'ARCH':<10}{'Architect Review'.ljust(26)}{agent_col}"
            f": {_fmt_duration(stats['arch_secs']):>8}"
        )

    # Agents summary line.
    if stats["agents"]:
        pairs = [f"{a}={m}" for a, m in sorted(stats["agents"].items())]
        lines.append(f"  Agents              : {', '.join(pairs)}")

    # Tokens & cost — delegated to verify_run_costs.
    if cost and "error" not in cost:
        totals = cost.get("totals") or {}
        se = cost.get("subagent_estimate") or {}
        data_incomplete = se.get("data_incomplete", False)
        best_estimate = se.get("best_estimate")
        confidence = se.get("confidence", "heuristic")
        prefix = "~" if cost.get("billing") == "subscription" else ""
        billing = cost.get("billing") or "unknown"

        if data_incomplete and best_estimate is not None:
            # Hook data is structurally incomplete (sub-agents not captured).
            # Show the duration-based floor as the primary cost figure.
            run_secs = se.get("run_secs") or 0
            dur_str = f"{run_secs // 60}m {run_secs % 60}s" if run_secs else "unknown"
            lines.append(
                f"  Est. Cost           : {prefix}${best_estimate:.2f}"
                f"  (duration-based floor, run={dur_str})"
            )
            lines.append(
                f"    ⚠ Hook data       : sub-agent sessions not captured by "
                f"Claude Code hooks."
            )
            lines.append(
                f"    ⚠ Accuracy        : duration floor is a conservative lower "
                f"bound — use /usage for the exact figure."
            )
            lines.append(
                f"    Host-session only : {prefix}${totals.get('cost', 0):.4f}"
                f"  (pre-flight work only, NOT the full run cost)"
            )
        else:
            # Normal path: hook data is available.
            lines.append(
                f"  Tokens              : {totals.get('throughput', 0):,} total "
                f"(in: {totals.get('input', 0):,}, "
                f"out: {totals.get('output', 0):,}, "
                f"cache_write: {totals.get('cache_write', 0):,}, "
                f"cache_read: {totals.get('cache_read', 0):,})    "
                "[host session only — see note]"
            )
            lines.append(f"  Est. Cost           :")
            mix = cost.get("mixed_model_costs") or {}
            if mix:
                for model, entry in mix.items():
                    lines.append(
                        f"    {model:<15} rates   : "
                        f"{prefix}${entry.get('cached', 0):.4f} cached / "
                        f"{prefix}${entry.get('no_cache', 0):.4f} no cache"
                    )
            else:
                lines.append(
                    f"    cost              : "
                    f"{prefix}${totals.get('cost', 0):.4f}"
                )
            savings = totals.get("cache_savings_pct")
            if savings is not None:
                lines.append(f"    Cache savings     : {savings:.1f}%")
            lines.append(
                f"    Billing           : "
                f"{billing}{' (estimated)' if billing == 'subscription' else ''}"
            )
            warnings = cost.get("warnings") or []
            if any("Mixed models" in w for w in warnings) or total > 900:
                lines.append(
                    "    ⚠ Scope          : host session ONLY — sub-agent token spend "
                    "(STRIDE ×N, triage, merger,"
                )
                lines.append(
                    "                        QA, architect) is NOT captured by "
                    "Claude Code's hook infrastructure."
                )
                lines.append(
                    "                        True cost for thorough runs is "
                    "typically 5–10× the number shown above."
                )
            # Show best_estimate as a supplementary line when it differs meaningfully
            if best_estimate is not None and best_estimate > totals.get("cost", 0) * 1.5:
                lines.append(
                    f"    Est. all agents   : {prefix}${best_estimate:.2f}"
                    f"  [{confidence} — includes sub-agent estimate]"
                )
    elif cost is None:
        lines.append("  Tokens/Cost         : unavailable (verify_run_costs.py failed)")
    return lines


def render_files(output_dir: Path, cfg: dict) -> list[str]:
    lines = [f"  -- Files {SECTION_RULE[:50]}"]
    lines.append(f"    {output_dir}/threat-model.md")
    if cfg.get("write_yaml", True):
        lines.append(f"    {output_dir}/threat-model.yaml")
    sarif = output_dir / "threat-model.sarif.json"
    if cfg.get("write_sarif") and sarif.is_file():
        lines.append(f"    {sarif}")
    arch_md = output_dir / ".architect-review.md"
    if cfg.get("architect_review") and arch_md.is_file():
        lines.append(
            f"    {arch_md}                 ← architect review (advisory)"
        )
    analysis_md = output_dir / "analysis-model.md"
    if analysis_md.is_file():
        lines.append(
            f"    {analysis_md}                    "
            "← architecture snapshot (pre-STRIDE)"
        )
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


def render_run_issues(data: Optional[dict]) -> list[str]:
    """Render the conditional `-- Run Issues --` block. Returns empty list
    on clean runs so the caller can extend unconditionally."""
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
        fr = issue.get("fix_recommendation") or {}
        if fr.get("auto_applicable"):
            lines.append(f"                        ↳ Auto-fix available: {fr.get('summary', '')[:70]}")
        else:
            lines.append(f"                        ↳ Manual review: {fr.get('category', '?')}")

    if len(issues) > 2:
        lines.append(f"                        ({len(issues) - 2} more in §Run Issues appendix)")

    if n_auto > 0:
        lines.append(f"  Auto-applicable     : {n_auto} of {len(issues)} fix(es) ready to apply")
        lines.append("  Apply fixes         : /appsec-advisor:fix-run-issues")

    lines.append("  See `## Appendix: Run Issues` in threat-model.md for the full breakdown.")
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
    is_clean = (
        not warnings
        and not section_retries
        and auto_retries == 0
    )
    if is_clean:
        return None

    return {
        "status":          "warned",
        "warning_count":   len(warnings),
        "warnings":        warnings,
        "section_retries": section_retries,
        "auto_retries":    auto_retries,
    }


def render_composition_health(health: Optional[dict]) -> list[str]:
    """Render the conditional Composition Health block. Returns an empty
    list when health is None (clean run) so the caller can extend
    unconditionally."""
    if not health:
        return []
    lines: list[str] = []
    lines.append("  -- Composition Health -------------------------------------")
    n_warn  = health["warning_count"]
    n_retry = sum(health["section_retries"].values()) if health["section_retries"] else 0
    n_auto  = health["auto_retries"]
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
        retry_str = ", ".join(
            f"§{sid} ({n}/3)" for sid, n in sorted(health["section_retries"].items())
        )
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
            lines.append(
                f"                        ({len(health['warnings']) - 2} more "
                f"in §Composition Notes appendix)"
            )

    if n_auto:
        lines.append(
            f"  Auto-retries        : {n_auto} inline-shortcut recovery cycle"
            f"{'s' if n_auto != 1 else ''} (succeeded)"
        )

    lines.append(
        "  See `## Appendix: Composition Notes` in threat-model.md for the full picture."
    )
    lines.append("")
    return lines


def render_next_steps(next_steps: list[str]) -> list[str]:
    if not next_steps:
        return []
    lines = [""]
    lines.append(f"  -- Next Steps {SECTION_RULE[:46]}")
    for i, step in enumerate(next_steps, start=1):
        lines.append(f"    {i}. {step}")
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
    lines.append(f"  -- Security Notice {SECTION_RULE[:41]}")
    lines.append(
        "  ⚠  threat-model.md is NOT git-ignored and may be committed."
    )
    lines.append(
        "     Threat reports contain sensitive vulnerability details,"
    )
    lines.append(
        "     attack vectors, and architecture weaknesses."
    )
    lines.append(
        "     Add  docs/security/  to .gitignore to keep them out of git."
    )
    lines.append(
        "     To publish deliberately (private repo, policy permits it):"
    )
    lines.append(
        "       /appsec-advisor:publish-threat-model"
    )
    lines.append(
        "     The publish skill runs pre-flight checks and patches .gitignore."
    )
    return lines


def render_log_files(output_dir: Path) -> list[str]:
    lines = [""]
    lines.append(f"  -- Log Files {SECTION_RULE[:47]}")
    lines.append(f"    Hook events : {output_dir}/.hook-events.log")
    lines.append(f"    Agent run   : {output_dir}/.agent-run.log")
    qa_status = output_dir / ".qa-status.json"
    if qa_status.is_file():
        lines.append(f"    QA status   : {qa_status}")
    return lines


def render_summary(
    output_dir: Path,
    repo_root: Path,
    cfg: dict,
    plugin_root: Path,
) -> str:
    yaml_data = _load_yaml(output_dir / "threat-model.yaml")
    md_text   = _load_text(output_dir / "threat-model.md")
    metrics   = extract_metrics(yaml_data, md_text)
    change    = extract_change_summary(yaml_data)
    stats     = extract_run_statistics(output_dir, yaml_data)
    cost      = extract_costs(output_dir, plugin_root)
    next_steps = build_next_steps(output_dir, repo_root, metrics, cfg)

    lines: list[str] = []
    lines.append(RULE)
    lines.append("  ASSESSMENT COMPLETE — Summary follows")
    lines.append(RULE)
    lines.append("")
    lines.append(f"  Repository          : {repo_root}")

    mode_line = f"  Mode                : {cfg.get('mode', 'full')}"
    if change:
        mode_line += (
            f"   (delta: +{change['added_n']} / ~{change['changed_n']} / "
            f"-{change['resolved_n']})"
        )
    lines.append(mode_line)
    lines.append("")

    lines.extend(render_files(output_dir, cfg))

    if change:
        lines.extend(render_change_summary(change))

    lines.extend(render_metrics(metrics, cfg))
    lines.extend(render_run_statistics(stats, cost))
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
    lines.extend(render_run_issues(run_issues))
    lines.extend(render_next_steps(next_steps))
    lines.extend(render_security_notice(output_dir))
    lines.extend(render_log_files(output_dir))
    lines.append("")
    lines.append(RULE)

    return "\n".join(lines) + "\n"


def render_dry_run(output_dir: Path, repo_root: Path) -> str:
    yaml_data = _load_yaml(output_dir / "threat-model.yaml")
    md_text   = _load_text(output_dir / "threat-model.md")
    metrics   = extract_metrics(yaml_data, md_text)
    ms_block  = _extract_management_summary(md_text)

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
        f"missing: {cs['missing']})"
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


def _extract_management_summary(md_text: str) -> str:
    m = _MS_SLICE_RE.search(md_text)
    if not m:
        return ""
    body = m.group(1)
    # Strip HTML for plain-console readability.
    body = re.sub(r"<blockquote[^>]*>", "", body)
    body = re.sub(r"</blockquote>", "", body)
    body = re.sub(r"<br\s*/?>", "\n", body)
    body = re.sub(r'\sstyle="[^"]*"', "", body)
    return body.strip()


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
    assess_dur = (
        _fmt_duration(stats["assess_secs"]) if stats["assess_secs"] else "n/a"
    )
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


def _bool_pair(parser: argparse.ArgumentParser, name: str, dest: str,
               default: bool, help_on: str = "", help_off: str = "") -> None:
    """Register --foo / --no-foo as a mutually-exclusive boolean pair."""
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(f"--{name}", dest=dest, action="store_true",
                     default=default, help=help_on)
    grp.add_argument(f"--no-{name}", dest=dest, action="store_false",
                     help=help_off)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="render_completion_summary.py",
                                description=__doc__.splitlines()[0])
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--repo-root",  type=Path, required=True)
    p.add_argument("--mode", default="full",
                   choices=("full", "incremental", "rebuild", "dry-run"))
    p.add_argument("--reasoning-model", default="opus-cheap",
                   choices=("opus-cheap", "sonnet", "opus", "haiku-economy"))
    _bool_pair(p, "write-yaml",        "write_yaml",        True)
    _bool_pair(p, "write-sarif",       "write_sarif",       False)
    _bool_pair(p, "write-pentest-tasks","write_pentest_tasks", False)
    _bool_pair(p, "check-requirements","check_requirements", False)
    _bool_pair(p, "architect-review",  "architect_review",  False)
    _bool_pair(p, "with-sca",          "with_sca",          False)
    p.add_argument("--patch-placeholders", action="store_true")
    p.add_argument("--no-print", dest="no_print", action="store_true",
                   help="Suppress the rendered completion summary on stdout. "
                        "Useful when invoked solely to patch placeholders "
                        "(e.g. from Stage 2 where the skill renders the final "
                        "summary itself after Stage 3).")
    p.add_argument("--plugin-root", type=Path,
                   default=Path(__file__).resolve().parent.parent)
    args = p.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"error: output_dir not a directory: {args.output_dir}",
              file=sys.stderr)
        return 2

    cfg = {
        "mode":                args.mode,
        "reasoning_model":     args.reasoning_model,
        "write_yaml":          args.write_yaml,
        "write_sarif":         args.write_sarif,
        "write_pentest_tasks": args.write_pentest_tasks,
        "check_requirements":  args.check_requirements,
        "architect_review":    args.architect_review,
        "with_sca":            args.with_sca,
    }

    if args.mode == "dry-run":
        print(render_dry_run(args.output_dir, args.repo_root), end="")
        return 0

    md_path = args.output_dir / "threat-model.md"
    if not md_path.is_file():
        print(f"error: threat-model.md not found in {args.output_dir}",
              file=sys.stderr)
        return 2

    # Compute stats once; used for patching + rendering.
    yaml_data = _load_yaml(args.output_dir / "threat-model.yaml")
    stats = extract_run_statistics(args.output_dir, yaml_data)

    if args.patch_placeholders:
        patch_placeholders(args.output_dir, stats)

    if not args.no_print:
        print(render_summary(args.output_dir, args.repo_root, cfg, args.plugin_root),
              end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
