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
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN_ROOT = HERE.parent


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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="appsec_status.py",
                                description="Read-only plugin status dump.")
    p.add_argument("--repo-root", default=os.getcwd())
    p.add_argument("--output-dir", default=None,
                   help="Override output directory (default: <repo>/docs/security).")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else (repo_root / "docs" / "security")

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
