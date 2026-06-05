#!/usr/bin/env python3
"""Remove transient artifacts from $OUTPUT_DIR after a successful assessment.

Runs as a post-pipeline step called by the skill layer (SKILL.md → Completion
Summary → skill-level cleanup). It is **idempotent** — safe to invoke more
than once, on partial runs, or on a completed run that already cleaned up.

Why a standalone script:

  The original design had Phase 11 emit the cleanup as an inline Bash block
  in the orchestrator's turn budget. Observed in 2026-04-21 production runs:
  the orchestrator skipped the block on ~50% of incremental runs because
  turn budget pressure shifted focus to the primary md-compose task. The
  Bash block was documented, but nothing enforced its execution.

  Making cleanup its own deterministic script removes the dependency on
  LLM compliance: the skill calls it unconditionally after Stage 3 (QA) and
  Stage 4 (architect-review) complete, regardless of whether the orchestrator
  emitted its own inline cleanup earlier.

Whitelist (pinned — also tested by tests/test_runtime_cleanup.py):

  Always-cleanup (orchestrator Phase 11 artifacts):
    .merge-candidates.json
    .merge-decisions.json
    .management-summary-draft.md
    .phase-epoch
    .session-agent-map
    .assessment-summary-emitted
    .prior-findings-index.json
    .stage1-resume-count
    .skill-config.json
    .recon-patterns.json
    .route-inventory.json
    .architecture-coverage.json
    .arch-coverage-threats.json
    .context-resolver.stdout
    .ctx-resolver.pid
    .recon-scanner.pid
    .recon-scanner.stdout
    .coverage-gaps.json
    .scan-manifest.txt
    .triage-ranking.json
    .qa-prepass.json
    .appsec-progress.json             latest live progress state
    .progress/                       (directory)
    .taxonomy-slices/                (directory)
    .dispatch-context/               (directory)
    .merge-context/                  (directory)

  Post-QA cleanup (only after QA reviewer finishes):
    .qa-status.json                  only when status=pass
    .qa-repair-plan.json             only when the plan is empty or absent
    .pre-render-report.json          bulk fragment-validation report
    .pre-render-repair-plan.json     compose-time fragment repair plan
    .inline-shortcut-retry-count     M2.13 auto-retry loop bookkeeping
    .inline-shortcut-repair-plan.json M2.13 hard-gate repair plan
    .compose-stats.json              M2.14 compose stats — surfaced in MD §Composition Notes
    .run-issues.json                 M2.15 aggregated run issues + recommendations
    .run-issues-fixes.json           M2.15 audit trail of fixes applied via fix-run-issues
    .fragments/                      (directory — compose inputs)

  Post-architect cleanup (only after Stage 4 finishes):
    .architect-status.json           only when status=pass
    .architect-repair-plan.json      only when the plan is empty or absent

  NEVER cleaned (audit trail and baseline cache):
    .threat-modeling-context.md
    .recon-summary.md
    .sca-practice-findings.json      (Phase 10 — sca-practice MF sidecar)
    .known-bad-libs-findings.json    (Phase 10 — known-bad-libs MF sidecar)
    .dep-update-activity.json        (Phase 10 — passive git-log cadence)
    .threats-merged.json
    .triage-flags.json
    .architect-review.md
    .requirements.yaml
    .stride-*.json
    .appsec-cache/
    .appsec-checkpoint              (cleared separately by Phase 11)
    .agent-run.log[.1.2]
    .hook-events.log[.1.2]
    threat-model.md / .yaml / .sarif.json / .pdf / pentest-tasks.yaml / analysis-model.md

Safety gates — skip entire cleanup when any of these hold:

  * KEEP_RUNTIME_FILES=true in env, or `--keep-runtime-files` flag
  * threat-model.md does not exist (run did not complete)
  * `.agent-run.log` contains an AGENT_ERROR in its last 100 lines

Invocation:

  python3 runtime_cleanup.py <OUTPUT_DIR> [--stage all|pre-qa|post-qa|post-architect]
                                          [--keep-runtime-files]
                                          [--force]                        # bypass safety gates
                                          [--json]

Exit codes:
  0 — cleanup ran (or was correctly skipped with a documented reason)
  1 — cleanup was blocked by a safety gate
  2 — invalid invocation (bad args, OUTPUT_DIR missing)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from event_log import format_line

# --- whitelist -------------------------------------------------------------

ALWAYS_FILES = [
    ".merge-candidates.json",
    ".merge-decisions.json",
    ".management-summary-draft.md",
    ".phase-epoch",
    ".session-agent-map",
    ".assessment-summary-emitted",
    ".assessment-owner-sid",
    ".prior-findings-index.json",
    ".stage1-resume-count",
    # M3.3 — these were left behind on prior crashed runs and accumulated
    # over time, polluting subsequent /appsec-advisor:status reports.
    ".skill-config.json",
    ".recon-patterns.json",
    # Sub-agent stdout/pid files written by context-resolver and recon-scanner
    # agents — always transient, never needed after the run completes.
    ".context-resolver.stdout",
    ".ctx-resolver.pid",
    ".recon-scanner.pid",
    ".recon-scanner.stdout",
    # Coverage-gaps index written by the STRIDE fan-out phase; obsolete after
    # merge and triage complete.
    ".coverage-gaps.json",
    # Scan manifest written when --scan-manifest is passed; transient audit
    # file that belongs to the run, not to the persisted threat model.
    ".scan-manifest.txt",
    # Triage ranking written by triage_compute_ranking.py; the canonical
    # output is threat-model.yaml, so the intermediate file can be reaped.
    ".triage-ranking.json",
    # Deterministic QA pre-pass handoff; durable status is .qa-status.json
    # until post-QA cleanup and report content after completion.
    ".qa-prepass.json",
    # Latest live progress state written by log_event.py. The durable audit
    # trail remains .agent-run.log; this file is only for in-flight status UI.
    ".appsec-progress.json",
    # M3.6 — self-liveness counter for skill_watchdog.py. One file, two
    # short lines (iter count + epoch); strictly transient.
    ".skill-watchdog.tick",
    # Architecture-coverage delivery (arch.md §Pipeline-Integration) —
    # all three are deterministic Phase 2.6 / 9 intermediates. The
    # promoted findings live in threats-merged / threat-model.yaml; these
    # files exist only for cross-phase wiring and have no value after
    # finalization.
    ".route-inventory.json",
    ".architecture-coverage.json",
    ".arch-coverage-threats.json",
]
ALWAYS_DIRS = [
    ".progress",
    ".taxonomy-slices",
    # Component-scoped volatile JSON slices passed to STRIDE analyzers by path
    # instead of inline prompt blobs.
    ".dispatch-context",
    # Focused merger context passed by path instead of inline prompt JSON.
    ".merge-context",
    # M3.6 — per-tool-call markers written by agent_logger PreToolUse +
    # removed by PostToolUse. Sub-agent calls without propagating Post may
    # leave stale markers; the post-run cleanup wipes them so the next
    # run's status --live starts from a clean slate.
    ".active-tool-calls",
]
POST_QA_FILES_IF_PASS = [
    ".qa-status.json",
    ".qa-repair-plan.json",
    # Sprint 3A (M3.5) — content-repair plan from the QA reviewer. Reaped
    # on a clean QA run (after the applier has been called). When QA is
    # not clean, the file is preserved so the user can inspect what the
    # applier tried to do.
    ".qa-content-repair-plan.json",
    ".pre-render-report.json",
    ".pre-render-repair-plan.json",
    # M2.13 — Sprint 4 auto-retry-loop bookkeeping. Reaped on successful
    # completion (this branch only runs when QA passed). On exit 2 /
    # exhausted-retries the skill bypasses this cleanup entirely, so the
    # user's exhausted-retries banner can point at these files.
    ".inline-shortcut-retry-count",
    ".inline-shortcut-repair-plan.json",
    # M2.14 — Sprint 6 observability. Reaped on success; the canonical
    # persistence is the §Composition Notes appendix in threat-model.md
    # (which compose embeds before this cleanup runs). Keeping the JSON
    # around after a successful run would just duplicate the data.
    ".compose-stats.json",
    # M2.15 — Sprint 7 observability. Reaped on success; the canonical
    # persistence is the §Run Issues appendix in threat-model.md.
    # The .run-issues-fixes.json (audit trail) is also reaped — applied
    # fixes are visible via git diff anyway.
    ".run-issues.json",
    ".run-issues-fixes.json",
    # Wall-clock timing markers. The start epoch is written at run start and
    # the elapsed seconds at completion; the rendered figure is already in the
    # §Run Statistics block, so the markers are transient. Self-healing
    # regardless (each run overwrites them), but reaped here to keep the dir
    # clean on non-keep-runtime-files runs.
    ".scan-start-epoch",
    ".scan-wall-seconds",
]
POST_QA_DIRS = [
    ".fragments",
]
POST_ARCH_FILES_IF_PASS = [
    ".architect-status.json",
    ".architect-repair-plan.json",
]

# Defensive — paths that must NEVER be deleted regardless of any other flag.
NEVER = {
    ".threat-modeling-context.md",
    ".recon-summary.md",
    ".sca-practice-findings.json",
    ".known-bad-libs-findings.json",
    ".dep-update-activity.json",
    ".threats-merged.json",
    ".triage-flags.json",
    ".architect-review.md",
    ".requirements.yaml",
    ".appsec-cache",
    ".appsec-checkpoint",
    ".agent-run.log",
    ".hook-events.log",
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",
    "threat-model.pdf",
    "threat-model.html",
    "pentest-tasks.yaml",
    "analysis-model.md",
}


def _status_file_is_pass(path: Path) -> bool:
    """Return True if the status JSON file indicates a clean pass.

    Missing file counts as pass — a completed run that never emitted a
    repair-plan is the success path for that stage.
    """
    if not path.is_file():
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    status = (data.get("status") or "").lower()
    return status in {"pass", "ok", "clean"}


def _repair_plan_is_empty(path: Path) -> bool:
    """Return True if the repair-plan JSON has zero issues (or is absent)."""
    if not path.is_file():
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return int(data.get("issue_count") or 0) == 0


def _has_agent_error(log_path: Path) -> bool:
    """Scan the tail of .agent-run.log for AGENT_ERROR entries."""
    if not log_path.is_file():
        return False
    try:
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    tail = lines[-100:] if len(lines) > 100 else lines
    return any("AGENT_ERROR" in line for line in tail)


def run_cleanup(
    output_dir: Path,
    stage: str,
    keep_runtime_files: bool,
    force: bool,
) -> dict[str, Any]:
    """Execute the cleanup. Returns a structured report (also written to log)."""
    report: dict[str, Any] = {
        "stage": stage,
        "output_dir": str(output_dir),
        "skipped": False,
        "skip_reason": None,
        "removed": [],
        "preserved": [],
        "not_present": [],
    }

    if not output_dir.is_dir():
        report["skipped"] = True
        report["skip_reason"] = f"output_dir not a directory: {output_dir}"
        return report

    # --- safety gates --------------------------------------------------------
    if not force:
        env_keep = os.environ.get("KEEP_RUNTIME_FILES", "").lower() == "true"
        if keep_runtime_files or env_keep:
            report["skipped"] = True
            report["skip_reason"] = "opt-out (--keep-runtime-files / KEEP_RUNTIME_FILES=true)"
            return report
        if not (output_dir / "threat-model.md").is_file():
            report["skipped"] = True
            report["skip_reason"] = "threat-model.md missing — run incomplete"
            return report
        if _has_agent_error(output_dir / ".agent-run.log"):
            report["skipped"] = True
            report["skip_reason"] = "AGENT_ERROR present in recent log lines"
            return report

    # --- resolve which paths are in scope for this stage --------------------
    files: list[str] = []
    dirs: list[str] = []
    if stage in {"all", "pre-qa"}:
        files.extend(ALWAYS_FILES)
        dirs.extend(ALWAYS_DIRS)
    if stage in {"all", "post-qa"}:
        qa_status_ok = _status_file_is_pass(output_dir / ".qa-status.json")
        qa_plan_ok = _repair_plan_is_empty(output_dir / ".qa-repair-plan.json")
        if qa_status_ok and qa_plan_ok:
            files.extend(POST_QA_FILES_IF_PASS)
            dirs.extend(POST_QA_DIRS)
        else:
            report["preserved"].append(".qa-status.json / .qa-repair-plan.json — QA not clean")
    if stage in {"all", "post-architect"}:
        arch_status_ok = _status_file_is_pass(output_dir / ".architect-status.json")
        arch_plan_ok = _repair_plan_is_empty(output_dir / ".architect-repair-plan.json")
        if arch_status_ok and arch_plan_ok:
            files.extend(POST_ARCH_FILES_IF_PASS)
        else:
            report["preserved"].append(".architect-status.json / .architect-repair-plan.json — architect not clean")

    # --- perform the removals ------------------------------------------------
    for name in files:
        if name in NEVER:
            # Paranoia — the whitelist itself must never contain a NEVER path.
            continue
        p = output_dir / name
        if p.is_file() or p.is_symlink():
            try:
                p.unlink()
                report["removed"].append(name)
            except OSError as e:
                report["preserved"].append(f"{name} — {e}")
        else:
            report["not_present"].append(name)

    for name in dirs:
        if name in NEVER:
            continue
        p = output_dir / name
        if p.is_dir():
            try:
                shutil.rmtree(p)
                report["removed"].append(f"{name}/")
            except OSError as e:
                report["preserved"].append(f"{name}/ — {e}")
        else:
            report["not_present"].append(f"{name}/")

    # --- log ----------------------------------------------------------------
    log_path = output_dir / ".agent-run.log"
    try:
        with log_path.open("a", encoding="utf-8") as f:
            if report["skipped"]:
                f.write(
                    format_line(
                        "RUNTIME_CLEANUP",
                        f"skipped ({report['skip_reason']})",
                        component="runtime-cleanup",
                    )
                )
            else:
                f.write(
                    format_line(
                        "RUNTIME_CLEANUP",
                        f"stage={stage} removed={len(report['removed'])} "
                        f"preserved={len(report['preserved'])}",
                        component="runtime-cleanup",
                    )
                )
    except OSError:
        pass  # non-fatal

    return report


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Remove transient artifacts after a successful assessment.")
    p.add_argument("output_dir", type=Path, help="Absolute path to $OUTPUT_DIR")
    p.add_argument(
        "--stage",
        choices=["all", "pre-qa", "post-qa", "post-architect"],
        default="all",
        help=(
            "Which wave to run. 'pre-qa' removes only orchestrator artifacts "
            "(safe to call before QA). 'post-qa' adds QA-specific artifacts. "
            "'post-architect' adds architect-review-specific artifacts. "
            "'all' is the union (default)."
        ),
    )
    p.add_argument("--keep-runtime-files", action="store_true")
    p.add_argument(
        "--force", action="store_true", help="Bypass safety gates (ignore KEEP_RUNTIME_FILES, missing md, log errors)."
    )
    p.add_argument("--json", action="store_true", help="Print structured JSON report")
    args = p.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"error: output_dir not a directory: {args.output_dir}", file=sys.stderr)
        return 2

    report = run_cleanup(
        output_dir=args.output_dir,
        stage=args.stage,
        keep_runtime_files=args.keep_runtime_files,
        force=args.force,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        if report["skipped"]:
            print(f"runtime-cleanup: skipped — {report['skip_reason']}")
        else:
            removed = len(report["removed"])
            preserved = len(report["preserved"])
            print(f"runtime-cleanup: stage={report['stage']}   removed={removed}   preserved={preserved}")
            for name in report["removed"]:
                print(f"  - removed   {name}")
            for note in report["preserved"]:
                print(f"  - preserved {note}")
    return 1 if report["skipped"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
