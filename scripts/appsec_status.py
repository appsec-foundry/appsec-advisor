#!/usr/bin/env python3
"""
appsec_status.py — Read-only status dump for the AppSec plugin.

Prints:
  * plugin version + analysis_version
  * available capsules (skills + hook)
  * last-run identity (if $OUTPUT_DIR has a baseline)
  * configuration source state (external context, requirements URL, steering)
  * fast-path preview (would the next run short-circuit?)

Invoked by the `/appsec-advisor:status` skill. No analysis is performed and
no files are written. The output is formatted for human reading; pass
`--json` to get a machine-readable structure instead.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN_ROOT = HERE.parent

# Phase budgets for the live-view age cutoff. Falls back to 300 s when the
# loader is unavailable.
sys.path.insert(0, str(HERE))
try:
    import phase_budgets  # type: ignore
except Exception:                                          # pragma: no cover
    phase_budgets = None  # type: ignore[assignment]


def _emit_table(title: str, rows: list[tuple[str, str]]) -> str:
    out = [f"\n{title}"]
    out.append("-" * len(title))
    max_key = max((len(k) for k, _ in rows), default=0)
    for k, v in rows:
        out.append(f"  {k.ljust(max_key)}  {v}")
    return "\n".join(out)


def _run_helper(script: str, *args: str) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            [sys.executable, str(HERE / script), *args],
            capture_output=True, text=True, timeout=15,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return 2, "", str(e)


def _load_plugin_json() -> dict:
    path = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _coach_status() -> tuple[str, str]:
    """Return (state, note) — 'active' / 'inactive' / 'unknown'."""
    env = os.environ.get("APPSEC_COACH", "").strip().lower()
    steering_cfg = _load_json(PLUGIN_ROOT / "hooks" / "steering_keywords.json") or {}
    cfg_enabled = bool(steering_cfg.get("enabled", False))
    truthy = {"1", "true", "yes", "on", "enable", "enabled"}
    falsy = {"0", "false", "no", "off", "disable", "disabled"}
    if env in truthy:
        return "active", "via APPSEC_COACH environment variable"
    if env in falsy:
        return "inactive", "forced off via APPSEC_COACH"
    if cfg_enabled:
        return "active", "via steering_keywords.json (enabled: true)"
    return "inactive", "opt-in — set APPSEC_COACH=1 or flip \"enabled\": true in steering_keywords.json"


def _config_summary(req_cfg_path: Path, plugin_cfg_path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    # External context endpoint
    plug_cfg = _load_json(plugin_cfg_path) or {}
    ctx = plug_cfg.get("external_context") or {}
    if ctx.get("enabled") and ctx.get("rest_url"):
        rows.append(("External context", f"REST endpoint -> {ctx['rest_url']}"))
    elif ctx.get("enabled") is False:
        rows.append(("External context", "disabled"))
    else:
        rows.append(("External context", "not configured (repo-files only)"))

    # Requirements YAML
    req_cfg = _load_json(req_cfg_path) or {}
    req_src = req_cfg.get("requirements_source") or {}
    url = req_src.get("requirements_yaml_url")
    enabled = bool(req_src.get("enabled", False))
    if url:
        cache = PLUGIN_ROOT / ".cache" / "requirements.yaml"
        cache_state = "cache present" if cache.is_file() else "no cache yet"
        rows.append(("Requirements YAML", f"{'auto-load ' if enabled else 'on-demand '}-> {url} ({cache_state})"))
    else:
        fallback = PLUGIN_ROOT / "data" / "appsec-requirements-fallback.yaml"
        fallback_state = "present" if fallback.is_file() else "missing"
        rows.append(("Requirements YAML", f"bundled fallback ({fallback_state})"))

    # Steering keywords
    steering_cfg = _load_json(PLUGIN_ROOT / "hooks" / "steering_keywords.json") or {}
    topic_count = len(steering_cfg.get("topics") or {})
    rows.append(("Steering topics", f"{topic_count} configured"))

    return rows


def _auto_clean_state(output_dir: Path) -> dict:
    """Run check_state --auto-clean and return a summary of what was removed.
    Never raises — any failure returns an empty result so status always prints."""
    code, out, _ = _run_helper(
        "check_state.py", str(output_dir), "--auto-clean", "--json",
    )
    if code != 0:
        return {"removed": [], "skipped": False}
    try:
        data = json.loads(out)
        clean = data.get("clean", {})
        return {
            "removed": clean.get("removed", []),
            "skipped": clean.get("skipped", False),
        }
    except (ValueError, json.JSONDecodeError):
        return {"removed": [], "skipped": False}


def _fast_path_preview(output_dir: Path, repo_root: Path) -> dict | None:
    """Run check-changes against the current working tree. Returns None if
    no baseline exists yet."""
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        return None
    code, out, _ = _run_helper(
        "baseline_state.py", "check-changes",
        "--output-dir", str(output_dir),
        "--repo-root", str(repo_root),
    )
    try:
        return {"exit": code, **json.loads(out)}
    except (ValueError, json.JSONDecodeError):
        return None


def _last_run_info(output_dir: Path) -> dict:
    code, out, _ = _run_helper(
        "baseline_state.py", "last-run-info",
        "--output-dir", str(output_dir),
    )
    if code != 0:
        return {"has_baseline": False}
    try:
        return json.loads(out)
    except (ValueError, json.JSONDecodeError):
        return {"has_baseline": False}


def render_text(data: dict) -> str:
    meta = data["plugin"]
    buf: list[str] = []

    cleaned = data.get("auto_clean", {}).get("removed", [])
    if cleaned:
        buf.append(f"⚠ Stale run-state cleaned automatically: {', '.join(cleaned)}")
        buf.append("")

    buf.append(f"AppSec Plugin v{meta.get('plugin_version', '?')}  "
               f"(analysis_version={meta.get('analysis_version', '?')})")
    buf.append("=" * 72)

    buf.append(_emit_table("Environment", [
        ("Plugin root", str(data["paths"]["plugin_root"])),
        ("Repo root",   str(data["paths"]["repo_root"])),
        ("Output dir",  str(data["paths"]["output_dir"])),
    ]))

    capsules = data["capsules"]
    buf.append(_emit_table("Capsules", [
        ("1. Threat Assessment", "/appsec-advisor:create-threat-model   [--help]"),
        ("2. Requirements Audit", "/appsec-advisor:check-appsec-requirements   [--help]"),
        ("3. Security Coach",    f"{capsules['coach']['state']} — {capsules['coach']['note']}"),
    ]))

    lr = data["last_run"]
    if lr.get("has_baseline"):
        buf.append(_emit_table("Last run", [
            ("Plugin version",   str(lr.get("plugin_version") or "?")),
            ("Analysis version", str(lr.get("analysis_version") or "?")),
            ("Commit SHA",       (lr.get("commit_sha") or "?")[:12]),
            ("Run at (UTC)",     str(lr.get("last_run_at") or "?")),
        ]))
    else:
        buf.append("\nLast run\n--------\n  (no baseline — first run will be a full assessment)")

    buf.append(_emit_table("Configuration sources", data["config"]))

    fp = data.get("fast_path")
    if fp:
        rows = [
            ("Baseline SHA", (fp.get("baseline_sha") or "?")[:12]),
            ("HEAD SHA",     (fp.get("head_sha") or "?")[:12]),
            ("Git diff",     f"{fp.get('committed_change_count', 0)} committed, "
                             f"{fp.get('working_tree_change_count', 0)} working-tree"),
            ("Fingerprint",  "match" if fp.get("fingerprint_match") else "changed"),
            ("Plugin drift", f"{fp['plugin_version']['tier']}"),
        ]
        decision_map = {
            0: "fast-abort — next incremental run would skip entirely",
            10: "fast-abort with plugin-drift advisory",
            1: "changes detected — incremental run will re-analyze",
        }
        rows.append(("Decision", decision_map.get(fp.get("exit"), "unknown")))
        buf.append(_emit_table("Fast-path preview (vs. current working tree)", rows))
    else:
        buf.append("\nFast-path preview\n----------------\n  (no baseline yet — not applicable)")

    buf.append("")  # trailing newline
    return "\n".join(buf)


def _live_snapshot(output_dir: Path) -> dict:
    """Snapshot of the in-flight run state (M3.6 #4).

    Reads three sources, all best-effort and silent on failure:

      * ``.appsec-lock`` — heartbeat freshness via ``check_state.classify``.
      * ``.active-tool-calls/*.json`` — per-call markers written by
        ``agent_logger.handle_pre_tool_use`` (M3.6 #2). Entries older than
        the phase-aware stall threshold are filtered out — sub-agent calls
        whose PostToolUse never propagates would otherwise show forever.
      * ``.progress/*.json`` — per-component substep state from
        STRIDE-analyzer sub-agents (and any other agent that adopts the
        same protocol).

    Returned dict shape (always present):
      * ``ts``                — wall-clock at snapshot time
      * ``has_run``           — bool; False = clean state, no live data
      * ``lock``              — classify-style summary or None
      * ``checkpoint``        — phase / status from ``.appsec-checkpoint``
      * ``threshold_seconds`` — phase-aware stall window applied to filtering
      * ``active_tool_calls`` — list of {tool_use_id, agent, tool, age_s,
                                input_summary} sorted oldest-first
      * ``progress``          — list of {component, step, label, age_s}
      * ``stride_files``      — count of completed ``.stride-*.json`` files
    """
    lock_path = output_dir / ".appsec-lock"
    cp_path = output_dir / ".appsec-checkpoint"
    active_dir = output_dir / ".active-tool-calls"
    progress_dir = output_dir / ".progress"

    has_lock = lock_path.is_file()
    has_active = active_dir.is_dir()
    has_progress = progress_dir.is_dir()
    if not (has_lock or has_active or has_progress):
        return {
            "ts": int(time.time()),
            "has_run": False,
            "lock": None,
            "checkpoint": None,
            "threshold_seconds": 0,
            "active_tool_calls": [],
            "progress": [],
            "stride_files": 0,
        }

    # Lock + checkpoint via check_state.classify (re-uses heartbeat parsing).
    try:
        from check_state import classify, _read_checkpoint  # type: ignore
        report = classify(output_dir)
    except Exception:
        report = {"state": "unknown", "lock": None, "checkpoint": None,
                  "reasons": []}
    cp = report.get("checkpoint") or {}
    phase = cp.get("phase")

    # Resolve threshold: phase from checkpoint, depth from skill-config.
    depth = "standard"
    sk = output_dir / ".skill-config.json"
    if sk.is_file():
        try:
            depth = (json.loads(sk.read_text(encoding="utf-8")).get(
                "assessment_depth") or depth)
        except (OSError, ValueError):
            pass
    if phase_budgets is not None:
        threshold = phase_budgets.threshold_for_phase(phase, depth)
    else:
        threshold = 300

    # Active tool calls — per-file scan, age-filtered.
    now = int(time.time())
    active: list[dict] = []
    if has_active:
        for f in sorted(active_dir.glob("*.json")):
            try:
                entry = json.loads(f.read_text(encoding="utf-8"))
                started = int(entry.get("started_at") or 0)
                age = max(0, now - started) if started else 0
                if started and age > threshold * 2:
                    # Stale Pre-only entry (sub-agent without propagating
                    # Post). Filter from the live view; do not delete —
                    # the next agent_logger Post may still arrive.
                    continue
                entry["age_s"] = age
                active.append(entry)
            except (OSError, ValueError):
                continue
    active.sort(key=lambda e: e.get("age_s", 0), reverse=True)

    # Progress files — same age treatment so a hung component is visible
    # but not eternally listed.
    progress: list[dict] = []
    if has_progress:
        for f in sorted(progress_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            try:
                age = max(0, now - int(f.stat().st_mtime))
            except OSError:
                age = 0
            progress.append({
                "component": data.get("component_name") or data.get("component_id") or f.stem,
                "step":      data.get("step"),
                "total":     data.get("total"),
                "label":     (data.get("label") or "").strip(),
                "age_s":     age,
            })
    progress.sort(key=lambda e: e.get("age_s", 0), reverse=True)

    stride_count = len(list(output_dir.glob(".stride-*.json")))

    return {
        "ts": now,
        "has_run": True,
        "lock": report.get("lock"),
        "checkpoint": cp or None,
        "threshold_seconds": threshold,
        "active_tool_calls": active,
        "progress": progress,
        "stride_files": stride_count,
    }


def _render_live(snap: dict) -> str:
    """Human-readable rendering of ``_live_snapshot`` output."""
    if not snap.get("has_run"):
        return "  (no run in progress — output dir has no lock / progress / active-tool markers)\n"

    cp = snap.get("checkpoint") or {}
    phase = cp.get("phase", "?")
    status = cp.get("status", "?")
    lock = snap.get("lock") or {}
    hb_age = lock.get("heartbeat_age")
    threshold = snap.get("threshold_seconds", 0)
    hb_str = f"{int(hb_age)}s" if hb_age is not None else "?"
    head = (
        f"  Phase {phase} (status={status})  "
        f"heartbeat_age={hb_str}  "
        f"stall_threshold={threshold}s  "
        f"stride_files={snap.get('stride_files', 0)}"
    )
    lines = [head]

    progress = snap.get("progress") or []
    if progress:
        lines.append("")
        lines.append("  In-flight components (.progress/):")
        for p in progress:
            step = p.get("step")
            total = p.get("total")
            label = p.get("label") or "?"
            step_str = f"[{step}/{total}]" if step and total else "[?]"
            lines.append(
                f"    {p.get('component', '?'):<24} {step_str:>10} "
                f"{label:<24} idle={p.get('age_s', 0)}s"
            )

    active = snap.get("active_tool_calls") or []
    if active:
        lines.append("")
        lines.append("  Active tool calls (.active-tool-calls/):")
        for a in active:
            agent = a.get("agent") or "?"
            tool = a.get("tool") or "?"
            age = a.get("age_s", 0)
            summary = a.get("input_summary") or ""
            lines.append(f"    [{age:>4}s] {agent:<22} {tool:<8} {summary}")
    elif progress:
        lines.append("")
        lines.append("  (no live tool-use markers — sub-agent activity may "
                     "still be in flight; check .progress above)")

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="appsec_status.py",
                                description="Read-only plugin status dump.")
    p.add_argument("--repo-root", default=os.getcwd())
    p.add_argument("--output-dir", default=None,
                   help="Override output directory (default: <repo>/docs/security).")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p.add_argument("--live", action="store_true",
                   help="Print only the in-flight run snapshot (active tool "
                        "calls, per-component progress, heartbeat freshness). "
                        "Honours --json. Skips the plugin / config / fast-path "
                        "tables — intended for fast cron-style polling.")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else (repo_root / "docs" / "security")

    if args.live:
        snap = _live_snapshot(output_dir)
        if args.json:
            print(json.dumps(snap, indent=2, sort_keys=True))
        else:
            print(_render_live(snap), end="")
        return 0

    auto_clean = _auto_clean_state(output_dir)
    plugin_json = _load_plugin_json()
    coach_state, coach_note = _coach_status()

    data = {
        "plugin": {
            "plugin_version": plugin_json.get("version", "unknown"),
            "analysis_version": plugin_json.get("analysis_version"),
            "compatible_analysis_versions": plugin_json.get("compatible_analysis_versions", []),
        },
        "paths": {
            "plugin_root": str(PLUGIN_ROOT),
            "repo_root": str(repo_root),
            "output_dir": str(output_dir),
        },
        "capsules": {
            "threat_assessment": {"command": "/appsec-advisor:create-threat-model"},
            "requirements_audit": {"command": "/appsec-advisor:check-appsec-requirements"},
            "coach": {"state": coach_state, "note": coach_note},
        },
        "last_run": _last_run_info(output_dir),
        "config": _config_summary(
            PLUGIN_ROOT / "skills" / "check-appsec-requirements" / "config.json",
            PLUGIN_ROOT / "config.json",
        ),
        "fast_path": _fast_path_preview(output_dir, repo_root),
        "auto_clean": auto_clean,
    }

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(render_text(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
