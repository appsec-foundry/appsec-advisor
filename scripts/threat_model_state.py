#!/usr/bin/env python3
"""
threat_model_state.py — read-only three-check health probe for the threat
model, used by ``/appsec-advisor:threat-model-state``.

Three checks, in order:

  3. Active run         → ``check_state.classify()``  (lock + heartbeat + checkpoint)
  1. Freshness          → ``baseline_state check-changes`` + ``baseline_state dirty-set``
                          (the SAME decision tree the create-threat-model skill
                          uses to fast-abort a run)
  2. Artifacts / debris → walk OUTPUT_DIR for transient files left behind by
                          a prior run; flag for ``/appsec-advisor:clean-state``
                          or ``runtime_cleanup.py`` per file class

Exit codes (CI gate):
  0  fresh and clean, no active run
  1  threat model stale or absent
  2  debris present (cleanup needed; freshness still OK)
  3  active run in progress (skip / retry later)
  4  unknown / error

Priority: an active run (3) shadows everything else; a stale verdict (1)
shadows debris (2); fresh + debris reports (2); fresh + clean reports (0).

The freshness verdict is derived from the same Python machinery the
create-threat-model skill uses for its pre-check, so the answers are
guaranteed consistent — no separate "is the model up to date?" heuristic
that drifts away from "would the next run actually do anything?".
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Imports from sibling scripts. All three are pure-Python modules with no
# import-time side effects.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:
    from check_state import classify as _classify_run
except Exception as e:  # pragma: no cover — import failures surfaced to user
    _classify_run = None  # type: ignore[assignment]
    _CLASSIFY_IMPORT_ERR: str | None = str(e)
else:
    _CLASSIFY_IMPORT_ERR = None


# ---------------------------------------------------------------------------
# Freshness — wraps `baseline_state.py check-changes` + `dirty-set` so the
# verdict is exactly what the create-threat-model skill would do.
# ---------------------------------------------------------------------------

# Verdict mapping:
#  check-changes →  dirty-set          → verdict
#  exit 0 (unchanged)        n/a       → FRESH
#  exit 2 (noise_only)       n/a       → FRESH
#  exit 10 (plugin-drift)    n/a       → STALE  (drift would trigger --full prompt)
#  exit 1 (changed)          exit 0    → STALE  (real component dirty)
#  exit 1 (changed)          exit 2    → FRESH  (only top-level globals; skill skips)
#  exit 1 (changed)          exit 3    → STALE  (potential new component)
#  exit 1 (changed)          err       → STALE  (conservative)
#  exit 3 (no_baseline / err)          → NO_MODEL or UNKNOWN

def _run_baseline(args: list[str]) -> tuple[int, dict]:
    """Run a baseline_state subcommand and parse JSON stdout. Returns
    ``(exit_code, parsed_json_or_empty_dict)``."""
    try:
        r = subprocess.run(
            [sys.executable, str(HERE / "baseline_state.py"), *args],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        return 4, {}
    payload: dict = {}
    try:
        payload = json.loads(r.stdout) if r.stdout.strip() else {}
    except (ValueError, json.JSONDecodeError):
        payload = {}
    return r.returncode, payload


def check_freshness(output_dir: Path, repo_root: Path) -> dict:
    """Mirror the create-threat-model pre-check decision tree.

    Returns a dict with at minimum:
      verdict       : "FRESH" | "STALE" | "NO_MODEL" | "UNKNOWN"
      reason        : short human-readable explanation
      check_changes : the parsed cmd_check_changes payload (or {})
      dirty_set     : the parsed cmd_dirty_set payload (or None)
      recommend     : "noop" | "incremental" | "full" | "rebuild" | "none"
    """
    yaml_path = output_dir / "threat-model.yaml"
    md_path = output_dir / "threat-model.md"
    if not yaml_path.is_file():
        if md_path.is_file():
            return {
                "verdict": "NO_MODEL",
                "reason": "legacy threat-model.md without yaml — bootstrap full run required",
                "check_changes": {},
                "dirty_set": None,
                "recommend": "full",
            }
        return {
            "verdict": "NO_MODEL",
            "reason": "no threat-model.yaml in output dir",
            "check_changes": {},
            "dirty_set": None,
            "recommend": "full",
        }

    cc_exit, cc_payload = _run_baseline([
        "check-changes",
        "--output-dir", str(output_dir),
        "--repo-root", str(repo_root),
    ])

    if cc_exit == 0:
        return {
            "verdict": "FRESH",
            "reason": "no source changes since baseline",
            "check_changes": cc_payload,
            "dirty_set": None,
            "recommend": "noop",
        }
    if cc_exit == 2:
        n = len(cc_payload.get("noise_only_changes", []) or [])
        return {
            "verdict": "FRESH",
            "reason": f"{n} noise-only file(s) — no security-relevant changes",
            "check_changes": cc_payload,
            "dirty_set": None,
            "recommend": "noop",
        }
    if cc_exit == 10:
        ver = cc_payload.get("plugin_version", {}) or {}
        return {
            "verdict": "STALE",
            "reason": (
                f"plugin upgraded ({ver.get('baseline','?')} → "
                f"{ver.get('current','?')}, tier={ver.get('tier','?')})"
            ),
            "check_changes": cc_payload,
            "dirty_set": None,
            "recommend": "full",
        }
    if cc_exit == 3:
        return {
            "verdict": "UNKNOWN",
            "reason": cc_payload.get("reason") or "check-changes returned exit 3",
            "check_changes": cc_payload,
            "dirty_set": None,
            "recommend": "none",
        }
    if cc_exit != 1:
        return {
            "verdict": "UNKNOWN",
            "reason": f"check-changes returned unexpected exit {cc_exit}",
            "check_changes": cc_payload,
            "dirty_set": None,
            "recommend": "none",
        }

    # cc_exit == 1: security-relevant changes exist; refine via dirty-set.
    rel_files = cc_payload.get("security_relevant_changes", []) or []
    if not rel_files:
        return {
            "verdict": "UNKNOWN",
            "reason": "check-changes reported exit 1 with empty relevant list",
            "check_changes": cc_payload,
            "dirty_set": None,
            "recommend": "none",
        }
    # Pass the file list as repeated --files args so we don't depend on stdin
    # routing through subprocess.
    ds_exit, ds_payload = _run_baseline([
        "dirty-set",
        "--output-dir", str(output_dir),
        "--no-stdin",
        "--files", *rel_files,
    ])

    if ds_exit == 0:
        return {
            "verdict": "STALE",
            "reason": (
                f"{len(ds_payload.get('dirty_component_ids', []))} component(s) dirty: "
                + ", ".join(ds_payload.get("dirty_component_ids", [])[:5])
            ),
            "check_changes": cc_payload,
            "dirty_set": ds_payload,
            "recommend": "incremental",
        }
    if ds_exit == 2:
        # Top-level globals or empty mapping — skill would fast-abort.
        return {
            "verdict": "FRESH",
            "reason": (
                f"{len(rel_files)} relevant file(s) but they map to no component "
                f"(top-level globals only) — incremental run would skip Stage 1"
            ),
            "check_changes": cc_payload,
            "dirty_set": ds_payload,
            "recommend": "noop",
        }
    if ds_exit == 3:
        return {
            "verdict": "STALE",
            "reason": (
                f"unmapped non-global file(s): "
                + ", ".join(ds_payload.get("unmapped_files", [])[:5])
                + " — possible new component"
            ),
            "check_changes": cc_payload,
            "dirty_set": ds_payload,
            "recommend": "incremental",
        }
    return {
        "verdict": "STALE",
        "reason": f"dirty-set returned unexpected exit {ds_exit} (conservative STALE)",
        "check_changes": cc_payload,
        "dirty_set": ds_payload,
        "recommend": "incremental",
    }


# ---------------------------------------------------------------------------
# Artifacts / debris detection — light wrapper over runtime_cleanup
# ---------------------------------------------------------------------------

# Tier-2 (post-run intermediates) inventory — imported from runtime_cleanup
# so the answer to "is this debris?" stays in sync with what
# ``runtime_cleanup.py --stage all`` would actually remove. Anything not
# listed here is treated as either required state (.appsec-cache, the
# threat-model.* products, .agent-run.log) or unknown user content.
try:
    from runtime_cleanup import (  # noqa: PLC0415
        ALWAYS_FILES as _RC_ALWAYS_FILES,
        ALWAYS_DIRS as _RC_ALWAYS_DIRS,
        POST_QA_FILES_IF_PASS as _RC_POST_QA_FILES,
        POST_QA_DIRS as _RC_POST_QA_DIRS,
        POST_ARCH_FILES_IF_PASS as _RC_POST_ARCH_FILES,
    )
    _TIER2_FILES = frozenset(_RC_ALWAYS_FILES + _RC_POST_QA_FILES + _RC_POST_ARCH_FILES)
    _TIER2_DIRS = frozenset(_RC_ALWAYS_DIRS + _RC_POST_QA_DIRS)
except Exception:  # pragma: no cover — defensive
    _TIER2_FILES = frozenset()
    _TIER2_DIRS = frozenset()

# Tier-1 (run-state orphans) — present only while a run is in flight; their
# survival post-run signals a crashed run that needs ``/clean-state``.
# These are NOT in runtime_cleanup's automatic sweep because they belong
# to the lock / heartbeat / checkpoint protocol, which clean-state owns.
_TIER1_FILES = frozenset({
    ".appsec-lock",
    ".skill-watchdog.tick",
    ".direct-write-blocked",
})


def _scan_artifacts(output_dir: Path) -> dict:
    """Walk output_dir top level and bucket transient files into tier 1 vs 2.

    Tier 1 — orphaned run-state (lock / watchdog tick / direct-write marker).
             These should be empty post-run. If present without an active
             heartbeat, the prior run crashed.
    Tier 2 — post-run intermediates that ``runtime_cleanup.py --stage all``
             would sweep. Authoritative list comes from runtime_cleanup.
    Required state (``.appsec-cache``, ``.appsec-checkpoint``, the
    threat-model.* products, ``.agent-run.log``, ``.hook-events.log``,
    ``.recon-summary.md`` etc.) is intentionally not flagged — those files
    appear in runtime_cleanup's NEVER-list and survive across runs.
    """
    tier1: list[str] = []
    tier2: list[str] = []
    if not output_dir.is_dir():
        return {"tier1": [], "tier2": []}
    try:
        entries = list(output_dir.iterdir())
    except OSError:
        return {"tier1": [], "tier2": []}

    for p in entries:
        name = p.name
        if p.is_file():
            if name in _TIER1_FILES:
                tier1.append(name)
            elif name in _TIER2_FILES:
                tier2.append(name)
        elif p.is_dir():
            if name in _TIER2_DIRS:
                tier2.append(name + "/")

    return {"tier1": sorted(tier1), "tier2": sorted(tier2)}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def collect(output_dir: Path, repo_root: Path) -> dict:
    """Run all three checks and return a structured payload."""
    out = {
        "ts": int(time.time()),
        "output_dir": str(output_dir),
        "repo_root": str(repo_root),
    }

    # Check 3 first — short-circuit when active.
    if _classify_run is not None:
        try:
            run_state = _classify_run(output_dir)
        except Exception as e:  # pragma: no cover — defensive
            run_state = {"state": "error", "reasons": [str(e)], "lock": None,
                         "checkpoint": None, "files": [], "needs_stage2": False}
    else:
        run_state = {"state": "error",
                     "reasons": [f"check_state import failed: {_CLASSIFY_IMPORT_ERR}"],
                     "lock": None, "checkpoint": None, "files": [],
                     "needs_stage2": False}
    out["active_run"] = run_state

    if run_state.get("state") == "active":
        # Skip checks 1 + 2 for sub-second response time.
        return out

    out["freshness"] = check_freshness(output_dir, repo_root)
    out["artifacts"] = _scan_artifacts(output_dir)
    return out


def exit_code_for(payload: dict) -> int:
    """Map the payload to one of the documented CI exit codes (0/1/2/3/4)."""
    run_state = (payload.get("active_run") or {}).get("state", "")
    if run_state == "active":
        return 3
    if run_state == "error":
        return 4

    fresh = payload.get("freshness") or {}
    verdict = fresh.get("verdict", "UNKNOWN")
    if verdict == "UNKNOWN":
        return 4
    if verdict in ("STALE", "NO_MODEL"):
        return 1

    artifacts = payload.get("artifacts") or {}
    if artifacts.get("tier1") or artifacts.get("tier2"):
        return 2
    return 0


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_text(payload: dict) -> str:
    buf: list[str] = []
    buf.append("══════════ Threat Model State ══════════")
    buf.append(f"  Repo       : {payload.get('repo_root')}")
    buf.append(f"  Output dir : {payload.get('output_dir')}")
    buf.append("")

    # Check 3 — active run
    run = payload.get("active_run") or {}
    state = run.get("state", "?")
    if state == "active":
        buf.append("[3] Active run        : RUNNING")
        for r in (run.get("reasons") or [])[:3]:
            buf.append(f"      • {r}")
        buf.append("")
        buf.append("  Checks 1 + 2 skipped while a run is in progress.")
        buf.append("════════════════════════════════════════")
        return "\n".join(buf) + "\n"

    if state == "clean":
        buf.append("[3] Active run        : no")
    elif state == "error":
        buf.append("[3] Active run        : UNKNOWN (check_state error)")
        for r in (run.get("reasons") or [])[:2]:
            buf.append(f"      • {r}")
    else:
        buf.append(f"[3] Active run        : {state}")
        if run.get("needs_stage2"):
            buf.append("      • Stage 1 complete, Stage 2 never dispatched — pass --resume")

    # Check 1 — freshness
    fr = payload.get("freshness") or {}
    verdict = fr.get("verdict", "?")
    icon = {"FRESH": "✓", "STALE": "⚠", "NO_MODEL": "✗", "UNKNOWN": "?"}.get(verdict, "?")
    buf.append(f"[1] Freshness         : {icon} {verdict}")
    if fr.get("reason"):
        buf.append(f"      Reason: {fr['reason']}")
    rec = fr.get("recommend", "none")
    rec_text = {
        "noop":        "no run needed — threat model is up to date",
        "incremental": "next /appsec-advisor:create-threat-model would run incremental",
        "full":        "run /appsec-advisor:create-threat-model --full",
        "rebuild":     "run /appsec-advisor:create-threat-model --rebuild",
        "none":        "—",
    }.get(rec, rec)
    buf.append(f"      Recommendation: {rec_text}")

    # Surface a few of the structured signals for the human reader.
    cc = fr.get("check_changes") or {}
    if cc:
        sec_count = cc.get("security_relevant_change_count", 0)
        noise_count = len(cc.get("noise_only_changes", []) or [])
        excluded = cc.get("excluded_pre_filter_count", 0)
        if sec_count or noise_count or excluded:
            buf.append(
                f"      Files: {sec_count} relevant / {noise_count} noise / "
                f"{excluded} excluded (plugin output / scan-excludes)"
            )
    ds = fr.get("dirty_set") or {}
    if ds and ds.get("dirty_component_ids"):
        buf.append(f"      Dirty components: {', '.join(ds['dirty_component_ids'])}")

    # Check 2 — artifacts
    art = payload.get("artifacts") or {}
    t1 = art.get("tier1") or []
    t2 = art.get("tier2") or []
    if not t1 and not t2:
        buf.append("[2] Artifacts         : ✓ none")
    else:
        buf.append(f"[2] Artifacts         : ⚠ {len(t1)} tier-1 / {len(t2)} tier-2")
        if t1:
            preview = ", ".join(t1[:6]) + (" …" if len(t1) > 6 else "")
            buf.append(f"      Tier 1 (run-state orphans): {preview}")
            buf.append("        → /appsec-advisor:clean-state to reap")
        if t2:
            preview = ", ".join(t2[:6]) + (" …" if len(t2) > 6 else "")
            buf.append(f"      Tier 2 (post-run intermediates): {preview}")
            buf.append("        → runtime_cleanup.py --stage all")

    buf.append("════════════════════════════════════════")
    return "\n".join(buf) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="threat_model_state.py", description=__doc__)
    p.add_argument("--repo-root", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--json", action="store_true",
                   help="Emit results as machine-readable JSON.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not repo_root.is_dir():
        print(f"Error: repo root not found: {repo_root}", file=sys.stderr)
        return 4

    payload = collect(output_dir, repo_root)
    code = exit_code_for(payload)
    payload["exit_code"] = code

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(payload), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
