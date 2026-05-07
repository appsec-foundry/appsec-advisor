#!/usr/bin/env python3
"""Hard gate that detects the Phase-11 inline-shortcut bypass.

Exit codes
----------
0   No bypass detected. Skill should proceed to Stage 3.
2   Inline-shortcut detected. Skill MUST NOT proceed — the rendered
    threat-model.md is structurally non-compliant.
3   Tool error (bad path, qa_checks not runnable, malformed output).

Why this script exists
----------------------
The detection logic previously lived as a Bash snippet inside
``skills/create-threat-model/SKILL-impl.md``. Because the skill body is
interpreted by an LLM, that "soft" interpretation occasionally let
broken runs slip through (the 2026-04-25 juice-shop Run 4 was the
canonical case). Promoting the logic to a stand-alone Python script
with a hard exit code makes the gate mechanical: ``|| exit $?`` cannot
be talked around.

Indicators (any one of which trips the gate, matching SKILL-impl.md
"Post-Stage-1 fragment precondition" section)
---------------------------------------------------------------------
A1  ``$OUTPUT_DIR/.fragments/`` directory missing entirely.
A2  ``.fragments/`` exists but contains < ``MIN_FRAGMENTS`` files.
B   ``.threats-merged.json`` missing while ``threat-model.md`` exists
    (Phase 9 merge step bypassed).
C   ``.triage-flags.json`` missing while ``threat-model.md`` exists
    (Phase 10b triage step bypassed) — only at standard+ depth.
D   ``threat-model.yaml`` exists but is missing required top-level
    arrays (``attack_surface``, ``trust_boundaries``, or
    ``security_controls``). These fields are populated from Phase 3–8
    working memory; when the finalization agent skips or truncates the
    YAML write they remain absent, which causes ``(0)`` empty tables
    across §2.4, §5, §7, and §9 even when the fragments look correct.
    This indicator fires post-Stage-2 (after ``threat-model.md`` exists)
    so the auto-retry loop can re-render from a corrected YAML.

Aggregator
----------
The script also re-runs ``qa_checks.py fragments`` and OR-merges its
exit code, so the upstream Required-fragment list (currently 8 entries
in ``REQUIRED_FRAGMENTS``) acts as a third independent indicator
without duplication of constants here.

Usage
-----
    python3 scripts/check_inline_shortcut.py <output-dir>
        [--depth quick|standard|thorough]
        [--write-repair-plan]   # Sprint 4 — currently a no-op stub.

The optional ``--write-repair-plan`` flag is reserved for Sprint 4
(auto-retry loop). Today it is accepted but ignored so callers can
already adopt the final invocation shape.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List


# Minimum fragment count below which we declare "structural bypass".
# The pipeline writes 8 required fragments under .fragments/; <3 means
# the orchestrator entered Phase 11 but never reached the fragment-
# writing substep in any meaningful way.
MIN_FRAGMENTS = 3

# Default plugin root layout — used to locate qa_checks.py.
PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def _detect_indicators(output_dir: Path, depth: str) -> List[str]:
    """Return human-readable bullet strings for every tripped indicator.

    Empty list = clean. Non-empty list = inline-shortcut.
    """
    reasons: List[str] = []
    frag_dir = output_dir / ".fragments"
    md_path = output_dir / "threat-model.md"
    threats_merged = output_dir / ".threats-merged.json"
    triage_flags = output_dir / ".triage-flags.json"

    # Indicator A1 — directory absent.
    if not frag_dir.is_dir():
        reasons.append(".fragments/ directory missing — orchestrator never entered the fragment substep")
        return reasons  # No point checking A2 if A1 already tripped.

    # Indicator A2 — directory empty / near-empty.
    files = [p for p in frag_dir.iterdir() if p.is_file() and p.suffix in (".md", ".json")]
    if len(files) < MIN_FRAGMENTS:
        reasons.append(
            f".fragments/ contains only {len(files)} files (< {MIN_FRAGMENTS} minimum; pipeline writes 8+) — "
            "orchestrator entered Phase 11 but skipped the fragment-writing substep"
        )

    # Indicator B — Phase 9 merge bypassed.
    if not threats_merged.is_file() and md_path.is_file():
        reasons.append(".threats-merged.json missing while threat-model.md exists — Phase 9 merge step bypassed")

    # Indicator C — Phase 10b triage bypassed (standard/thorough only).
    if depth != "quick" and not triage_flags.is_file() and md_path.is_file():
        reasons.append(".triage-flags.json missing while threat-model.md exists — Phase 10b triage step bypassed")

    # Indicator D — threat-model.yaml missing required Phase 3–8 arrays.
    # These fields are populated from working memory during Phase 11 Substep 2.
    # When the finalization agent skips or truncates the YAML write they are
    # absent, causing empty tables in §2.4, §5, §7, §9 even if the composed
    # Markdown looks well-formed. Check only when threat-model.md exists (i.e.
    # Stage 2 already ran) so this indicator fires in the post-Stage-2 gate.
    yaml_path = output_dir / "threat-model.yaml"
    if md_path.is_file() and yaml_path.is_file():
        try:
            import yaml as _yaml
            data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            for field in ("attack_surface", "trust_boundaries", "security_controls"):
                val = data.get(field)
                if not val:  # None, missing, or empty list
                    reasons.append(
                        f"threat-model.yaml: '{field}' is absent or empty — "
                        "Phase 3–8 data was not persisted to YAML by the finalization agent. "
                        "This causes empty §5/§7/§9 tables in the rendered report."
                    )
        except Exception as exc:
            reasons.append(f"threat-model.yaml could not be parsed for Indicator D check: {exc}")

    return reasons


def _run_qa_fragments_check(output_dir: Path) -> int:
    """Run ``qa_checks.py fragments`` and return its exit code.

    The upstream check carries its own REQUIRED_FRAGMENTS list — keeping
    the source-of-truth in qa_checks.py prevents drift.
    """
    qa_path = PLUGIN_ROOT / "scripts" / "qa_checks.py"
    if not qa_path.is_file():
        return 3
    try:
        result = subprocess.run(
            ["python3", str(qa_path), "fragments", str(output_dir)],
            capture_output=True, text=True, timeout=60,
        )
        return result.returncode
    except (subprocess.SubprocessError, OSError):
        return 3


def _print_banner(reasons: List[str], qa_exit: int, output_dir: Path) -> None:
    """Print the inline-shortcut banner mirroring SKILL-impl.md L1140-1158."""
    bar = "═" * 62
    print("", file=sys.stderr)
    print(bar, file=sys.stderr)
    print("  ASSESSMENT INCOMPLETE — inline-shortcut detected", file=sys.stderr)
    print(bar, file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "  Stage 1 produced threat-model.md without going through the",
        file=sys.stderr,
    )
    print("  fragment pipeline. Indicators that tripped:", file=sys.stderr)
    print("", file=sys.stderr)
    for r in reasons:
        print(f"    • {r}", file=sys.stderr)
    print(f"    • qa_checks.py fragments exit code: {qa_exit}", file=sys.stderr)
    print("", file=sys.stderr)
    # Check if any reasons are Indicator D (YAML content) vs structural bypass
    yaml_indicator = any("threat-model.yaml:" in r for r in reasons)
    struct_indicator = any("threat-model.yaml:" not in r for r in reasons)
    if struct_indicator:
        print("  Root cause: the orchestrator skipped Phase 11 Substep 4", file=sys.stderr)
        print("  (fragment authoring) and/or Phase 9 merge / Phase 10b triage,", file=sys.stderr)
        print("  then hand-authored the Markdown via a direct Write. The", file=sys.stderr)
        print("  contract-mandated renderers (compose_threat_model.py +", file=sys.stderr)
        print("  validate_fragment.py pre-render-gate) never ran, which means:", file=sys.stderr)
        print("    – the rendered report is structurally unverified", file=sys.stderr)
        print("    – findings IDs are not schema-validated", file=sys.stderr)
        print("    – the Re-Render Loop has nothing to rewrite", file=sys.stderr)
        print("    – future incremental runs lose carry-forward state", file=sys.stderr)
        print("      (.threats-merged.json / .triage-flags.json missing)", file=sys.stderr)
    if yaml_indicator:
        print("  Root cause (Indicator D): threat-model.yaml is missing required", file=sys.stderr)
        print("  Phase 3–8 arrays. The finalization agent wrote the YAML but", file=sys.stderr)
        print("  omitted attack_surface / trust_boundaries / security_controls —", file=sys.stderr)
        print("  data that was accumulated in working memory during Phases 3–8", file=sys.stderr)
        print("  but never persisted to the file. The rendered §5, §7, §9", file=sys.stderr)
        print("  sections show '(0) None enumerated' as a result.", file=sys.stderr)
        print("  Fix: re-run with --rebuild or --resume to redo Phase 11.", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Fix: re-run the skill. If this reproduces, file a plugin bug —", file=sys.stderr)
    print("  the Phase 11 substep templates in phase-group-finalization.md", file=sys.stderr)
    print("  must be enforced harder (every Write tool call should be", file=sys.stderr)
    print("  preceded by a Bash heartbeat + checkpoint update).", file=sys.stderr)
    print(bar, file=sys.stderr)
    print("", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_inline_shortcut.py",
        description="Hard gate detecting Phase-11 inline-shortcut bypass.",
    )
    parser.add_argument("output_dir", type=Path,
                        help="Assessment output directory (typically <repo>/docs/security).")
    parser.add_argument("--depth", choices=["quick", "standard", "thorough"],
                        default="standard",
                        help="Assessment depth — affects whether Indicator C (.triage-flags.json) is checked.")
    parser.add_argument("--write-repair-plan", action="store_true",
                        help="Reserved for Sprint 4 — write .inline-shortcut-repair-plan.json. Currently a no-op stub.")
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir
    if not output_dir.is_dir():
        print(f"Error: output directory does not exist: {output_dir}", file=sys.stderr)
        return 3

    reasons = _detect_indicators(output_dir, args.depth)
    qa_exit = _run_qa_fragments_check(output_dir)

    if not reasons and qa_exit == 0:
        return 0  # Clean — no bypass.

    _print_banner(reasons, qa_exit, output_dir)

    # Sprint-4 stub: write the repair plan so the skill can drive an
    # auto-retry loop. For Sprint 1 this is a no-op — caller still gets
    # exit 2 and is expected to abort the run.
    if args.write_repair_plan:
        plan_path = output_dir / ".inline-shortcut-repair-plan.json"
        plan = {
            "status": "fail",
            "kind": "inline_shortcut",
            "indicators": reasons,
            "qa_fragments_exit": qa_exit,
            "missing_fragments": _list_missing_fragments(output_dir),
            "schema_version": 1,
        }
        try:
            plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
            print(f"  → Repair plan written: {plan_path}", file=sys.stderr)
        except OSError as exc:
            print(f"  ⚠ Failed to write repair plan: {exc}", file=sys.stderr)

    return 2


def _list_missing_fragments(output_dir: Path) -> list[str]:
    """Best-effort enumeration of missing required fragments. Imports
    REQUIRED_FRAGMENTS from qa_checks lazily to avoid a hard dependency
    at module load time (and to keep this script runnable without the
    full plugin path being on sys.path).
    """
    try:
        sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
        from qa_checks import REQUIRED_FRAGMENTS  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        return []
    finally:
        if str(PLUGIN_ROOT / "scripts") in sys.path:
            sys.path.remove(str(PLUGIN_ROOT / "scripts"))

    frag_dir = output_dir / ".fragments"
    if not frag_dir.is_dir():
        return list(REQUIRED_FRAGMENTS)
    present = {p.name for p in frag_dir.iterdir() if p.is_file()}
    return [name for name in REQUIRED_FRAGMENTS if name not in present]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
