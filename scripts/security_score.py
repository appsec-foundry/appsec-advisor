#!/usr/bin/env python3
"""security_score.py — deterministic quick Security Score (0-100) for a repository.

A fast indication, not an assessment. The score runs the deterministic scanner
layer only: no agents, no LLM, no run state, nothing written into the target
repository. A full ``/appsec-advisor:create-threat-model`` run stays the
authority on severity and risk.

What the number means
---------------------
Two independent parts:

  * Control basis — the share of *applicable* architecture-coverage rules that
    found a control signal. ``architecture_coverage_checks.py`` decides per rule
    whether it applies at all (REQ-ARC-001: an absent surface is not
    applicable), which gives the score an honest denominator: rules that could
    not fire are excluded rather than counted as passes.
  * Finding penalty — a saturating deduction for the hard findings of the
    config/IaC and source-auth scanners, weighted by their catalog severity.

What it deliberately does NOT do
--------------------------------
There is no asset tier, no exposure, and no abuse chain here, so the severities
are catalog defaults and carry none of the caps and elevations the report
applies. Two repositories are therefore not comparable through this number; the
same repository across commits is.

Below ``MIN_APPLICABLE_RULES`` applicable rules the verdict is ``undetermined``
instead of a value. The rule catalog is language-bound (JS/TS, Python,
Java/Spring, parts of .NET), and a repository it does not cover would otherwise
score high purely for the absence of evidence.

Exit codes:
  0  score computed
  2  undetermined (too few applicable rules)
  1  error
"""

from __future__ import annotations

import argparse
import functools
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from scan_excludes import is_assessment_artifact  # noqa: E402

# Points per architecture-coverage status. `not_applicable` never reaches here —
# it is what keeps the denominator honest.
STATUS_POINTS = {
    "present": 1.0,
    "partial": 0.5,
    "weak": 0.25,
    "missing": 0.0,
    "anti_pattern": 0.0,
}

# Catalog severity → penalty points, summed into a raw weight.
SEVERITY_WEIGHT = {"critical": 8.0, "high": 4.0, "medium": 1.5, "low": 0.5}

# The raw weight is mapped through `CAP * raw / (raw + HALF)` rather than being
# clipped. A hard cap saturates: measured on two real repositories, both ran far
# past it and the penalty stopped separating them at all. The curve keeps small
# and mid-sized repositories apart, and past a few hundred weighted points it
# flattens on purpose — beyond that, "many findings" is the same statement.
PENALTY_CAP = 30.0
PENALTY_HALF_WEIGHT = 80.0

# Below this many applicable rules the sample is too small to divide by.
MIN_APPLICABLE_RULES = 5

# Readable category names come from the control catalog rather than a second
# vocabulary invented here, so the score names its categories exactly as the
# report does.
_CONTROLS_YAML = HERE.parent / "data" / "architectural-controls.yaml"

# Per-scanner wall-clock ceiling. A pathological repository must not hang the
# probe; a scanner that times out degrades the score to a warning, not a crash.
SCANNER_TIMEOUT_S = 600


@functools.lru_cache(maxsize=1)
def domain_labels() -> dict[str, str]:
    """Domain key → catalog label. Empty when the catalog is unreadable."""
    try:
        import yaml

        doc = yaml.safe_load(_CONTROLS_YAML.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — a missing label degrades to the raw key
        return {}
    labels = doc.get("domains") if isinstance(doc, dict) else None
    return labels if isinstance(labels, dict) else {}


def _run(argv: list[str], warnings: list[str], label: str) -> bool:
    """Run one scanner. Returns whether it produced output; never raises."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [sys.executable, *argv],
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        warnings.append(f"{label}: timed out, excluded")
        return False
    except OSError as exc:
        warnings.append(f"{label}: could not run, excluded ({exc})")
        return False
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit {proc.returncode}"
        warnings.append(f"{label}: failed, excluded ({tail})")
        return False
    return True


def _load(path: Path, warnings: list[str], label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        warnings.append(f"{label}: unreadable output, excluded ({exc})")
        return {}
    return data if isinstance(data, dict) else {}


def collect(repo_root: Path, work_dir: Path) -> tuple[list[dict], list[dict], list[str]]:
    """Run the deterministic scanners and return (rules, findings, warnings).

    Sidecars are written to ``work_dir`` — outside the target repository, so a
    probe leaves no artifact behind that a later run would have to exclude.
    """
    warnings: list[str] = []
    repo = str(repo_root)
    out = str(work_dir)

    # Route inventory first: three ARCH rules stay not_applicable without it.
    _run([str(HERE / "route_inventory.py"), "--repo-root", repo, "--output-dir", out], warnings, "route-inventory")

    rules: list[dict] = []
    if _run(
        [str(HERE / "architecture_coverage_checks.py"), "--repo-root", repo, "--output-dir", out],
        warnings,
        "architecture-coverage",
    ):
        data = _load(work_dir / ".architecture-coverage.json", warnings, "architecture-coverage")
        rules = [r for r in data.get("rules_evaluated") or [] if isinstance(r, dict)]

    findings: list[dict] = []
    scanners = (
        (
            "config-iac",
            [
                str(HERE / "config_iac_scanner.py"),
                "--repo-root",
                repo,
                "--output",
                str(work_dir / ".config-scan.json"),
            ],
            ".config-scan.json",
        ),
        (
            "source-auth",
            [str(HERE / "source_auth_scanner.py"), "--repo-root", repo, "--output-dir", out, "--quiet"],
            ".source-auth-findings.json",
        ),
    )
    for label, argv, sidecar in scanners:
        if not _run(argv, warnings, label):
            continue
        data = _load(work_dir / sidecar, warnings, label)
        findings.extend(f for f in data.get("findings") or [] if isinstance(f, dict))

    return rules, findings, warnings


def _drop_assessment_artifacts(findings: list[dict], repo_root: Path) -> tuple[list[dict], int]:
    """Drop findings located inside a previous assessment output directory.

    A prior report stored in the repository contains quoted source lines, and
    the config/IaC and source-auth scanners do not filter those directories
    themselves. Without this, an old report inflates the finding count of the
    repository it describes.
    """
    kept = [f for f in findings if not is_assessment_artifact(str(f.get("file") or ""), repo_root)]
    return kept, len(findings) - len(kept)


def _contaminated_rules(rules: list[dict], repo_root: Path) -> list[str]:
    """Rule ids whose every evidence line comes from a prior assessment output."""
    contaminated = []
    for rule in rules:
        evidence = [e for e in rule.get("evidence") or [] if isinstance(e, dict)]
        if not evidence:
            continue
        if all(is_assessment_artifact(str(e.get("file") or ""), repo_root) for e in evidence):
            contaminated.append(str(rule.get("rule_id") or "?"))
    return sorted(contaminated)


def finding_penalty(findings: list[dict]) -> tuple[float, dict[str, int]]:
    """Saturating severity-weighted deduction plus the per-severity tally."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    raw = 0.0
    for finding in findings:
        severity = str(finding.get("severity") or "").strip().lower()
        if severity not in SEVERITY_WEIGHT:
            continue
        counts[severity] += 1
        raw += SEVERITY_WEIGHT[severity]
    return PENALTY_CAP * raw / (raw + PENALTY_HALF_WEIGHT), counts


def compute(rules: list[dict], findings: list[dict]) -> dict[str, Any]:
    """Score the collected signals. Pure — no I/O, no subprocesses."""
    applicable = [r for r in rules if r.get("status") in STATUS_POINTS]
    penalty, counts = finding_penalty(findings)

    result: dict[str, Any] = {
        "rules_total": len(rules),
        "rules_applicable": len(applicable),
        "findings": counts,
        "findings_total": sum(counts.values()),
        "penalty": round(penalty),
        "categories": [],
    }

    if len(applicable) < MIN_APPLICABLE_RULES:
        result["verdict"] = "undetermined"
        result["score"] = None
        result["control_basis"] = None
        result["reason"] = (
            f"only {len(applicable)} of {len(rules)} rules applied to this repository "
            f"({MIN_APPLICABLE_RULES} required) — the rule catalog does not cover it"
        )
        return result

    earned = sum(STATUS_POINTS[r["status"]] for r in applicable)
    basis = 100.0 * earned / len(applicable)

    by_domain: dict[str, list[float]] = {}
    for rule in applicable:
        by_domain.setdefault(str(rule.get("domain") or "unknown"), []).append(STATUS_POINTS[rule["status"]])
    labels = domain_labels()

    result["verdict"] = "scored"
    result["control_basis"] = round(basis)
    result["score"] = max(0, round(basis - penalty))
    result["categories"] = sorted(
        (
            {
                "domain": domain,
                "label": labels.get(domain, domain),
                "points": round(100.0 * sum(points) / len(points)),
                "rules": len(points),
            }
            for domain, points in by_domain.items()
        ),
        key=lambda row: (row["points"], row["label"]),
    )
    return result


BAR_WIDTH = 10


def _bar(points: int) -> str:
    filled = round(BAR_WIDTH * points / 100)
    return "█" * filled + "·" * (BAR_WIDTH - filled)


def render_text(result: dict[str, Any]) -> str:
    """The human-readable report: a headline, the categories, then the caveats.

    The qualifiers ride in the second line rather than in a closing paragraph —
    the number must not travel without them, and prose would be skipped anyway.
    """
    counts = result["findings"]
    scan = f"quick scan · {result['rules_applicable']} of {result['rules_total']} rules · no exposure context"

    if result["verdict"] == "undetermined":
        return f"Security Score  undetermined\n{result['reason']}"

    lines = [f"Security Score  {result['score']} / 100", scan, ""]

    width = max((len(row["label"]) for row in result["categories"]), default=0)
    for row in result["categories"]:
        lines.append(f"  {row['label']:<{width}}  {row['points']:>3}  {_bar(row['points'])}  {row['rules']}")

    lines += [
        "",
        f"  controls {result['control_basis']} / 100 · findings -{result['penalty']}",
        f"  {counts['critical']} critical · {counts['high']} high · {counts['medium']} medium · {counts['low']} low",
    ]

    for warning in result.get("warnings") or []:
        lines += ["", f"  {warning}"]

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic quick Security Score (0-100) for a repository.")
    parser.add_argument("--repo", default=".", help="Repository to score (default: current working dir)")
    parser.add_argument("--json", action="store_true", help="Emit the result as machine-readable JSON")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo).expanduser().resolve()
    if not repo_root.is_dir():
        print(f"error: not a directory: {repo_root}", file=sys.stderr)
        return 1

    work_dir = Path(tempfile.mkdtemp(prefix="appsec-score-"))
    try:
        rules, findings, warnings = collect(repo_root, work_dir)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    findings, dropped = _drop_assessment_artifacts(findings, repo_root)
    if dropped:
        warnings.append(f"ignored {dropped} findings quoting a previous assessment in the repo")
    contaminated = _contaminated_rules(rules, repo_root)
    if contaminated:
        warnings.append("judged on a previous assessment's evidence: " + ", ".join(contaminated))

    result = compute(rules, findings)
    result["repo"] = str(repo_root)
    result["warnings"] = warnings

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_text(result))

    return 2 if result["verdict"] == "undetermined" else 0


if __name__ == "__main__":
    sys.exit(main())
