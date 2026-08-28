#!/usr/bin/env python3
"""security_score.py — deterministic quick Security Score (0-100) for a repository.

A fast indication, not an assessment. The score runs the deterministic scanner
layer only: no agents, no LLM, no run state, nothing written into the target
repository. A full ``/appsec-advisor:create-threat-model`` run stays the
authority on severity and risk.

What the number means
---------------------
One score per indicator — Output Handling, Access Control, Hardening and the
rest of ``data/security-score-indicators.yaml`` — each built from that
indicator's own signals:

  * the applicable architecture-coverage rules routed to it, where a rule that
    only raised a hypothesis earns a quarter of the credit a confirmed control
    earns. ``architecture_coverage_checks.py`` decides per rule whether it
    applies at all (REQ-ARC-001: an absent surface is not applicable), which
    gives each indicator an honest denominator.
  * that indicator's own findings from the config/IaC and source-auth scanners,
    as a saturating deduction weighted by catalog severity. Low never counts —
    every Low check states a build practice rather than a weakness — and
    repeated hits of one config check are damped, because a policy evaluated
    once per workflow file is still one policy.

The headline is the mean of the weaker half of the scored indicators. A
repository is attacked where it is weakest, and averaging everything lets a
well-covered aspect pay for a broken one.

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
import collections
import functools
import json
import math
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from scan_excludes import is_assessment_artifact  # noqa: E402
from weakness_classifier import classify_cwe  # noqa: E402

# Points per architecture-coverage status. `not_applicable` never reaches here —
# it is what keeps the denominator honest.
STATUS_POINTS = {
    "present": 1.0,
    "partial": 0.5,
    "weak": 0.25,
    "missing": 0.0,
    "anti_pattern": 0.0,
}

# Catalog severity → penalty points, summed into a raw weight. Low is absent on
# purpose: every Low check in the config catalog states a build practice (SBOM
# generation, a Renovate config, a Dockerfile HEALTHCHECK) rather than a
# weakness, and a security indication should not move on those.
SEVERITY_WEIGHT = {"critical": 8.0, "high": 4.0, "medium": 1.5}

# Repeated hits of one CONFIG check are damped to `weight * (1 + ln(n))`. A
# repository property evaluated per file — a missing workflow `permissions:`
# block, an unsigned image — fires once per workflow, and counted per hit five
# such checks made up 78% of the raw weight on a measured repository. One policy
# gap is one thing to fix. Source findings are not damped: a weakness at
# seventeen call sites is seventeen places to change.
DAMPED_SCANNERS = frozenset({"config-iac"})

# Per indicator, the raw weight is mapped through `CAP * raw / (raw + HALF)`
# rather than being clipped. A hard cap saturates: measured on two repositories,
# both ran past it and the penalty stopped separating them. The curve keeps the
# low end apart and flattens where "many findings" stops being a new statement.
# The cap spans the whole scale on purpose: an indicator carrying dozens of
# confirmed findings is not rescued by a rule reporting the control as present.
PENALTY_CAP = 100.0
PENALTY_HALF_WEIGHT = 40.0

# Below this many applicable rules the sample is too small to divide by.
MIN_APPLICABLE_RULES = 5

# How many distinct checks the finding list names.
TOP_FINDINGS = 10

# A rule's decision caps the control credit its status can earn: a hypothesis is
# not a control, and a threat candidate is a control that failed.
DECISION_CEILING = {
    "emit_control_only": 1.0,
    "emit_control_and_hypothesis": 0.25,
    "emit_hypothesis_only": 0.25,
    "emit_control_and_threat_candidate": 0.0,
    "emit_anti_pattern_candidate": 0.0,
}

# The indicator vocabulary and its CWE / weakness-class routing.
_INDICATORS_YAML = HERE.parent / "data" / "security-score-indicators.yaml"
_RULES_YAML = HERE.parent / "data" / "architecture-coverage-rules.yaml"

# Per-scanner wall-clock ceiling. A pathological repository must not hang the
# probe; a scanner that times out degrades the score to a warning, not a crash.
SCANNER_TIMEOUT_S = 600


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml

        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — a missing catalog degrades, never crashes
        return {}
    return doc if isinstance(doc, dict) else {}


@functools.lru_cache(maxsize=1)
def indicators() -> tuple[list[tuple[str, str]], dict[str, dict[str, str]], str]:
    """The indicator vocabulary: (order, routing tables, default).

    Routing tables are keyed by field name and consumed in the order
    :func:`indicator_for` applies them.
    """
    doc = _load_yaml(_INDICATORS_YAML)
    order: list[tuple[str, str]] = []
    tables: dict[str, dict[str, str]] = {
        field: {} for field in ("config_checks", "iac_types", "cwes", "weakness_classes", "scanners")
    }
    for entry in doc.get("indicators") or []:
        if not isinstance(entry, dict) or not entry.get("id"):
            continue
        indicator = str(entry["id"])
        order.append((indicator, str(entry.get("label") or indicator)))
        for field, table in tables.items():
            for value in entry.get(field) or []:
                key = str(value).strip()
                table.setdefault(key.upper() if field == "cwes" else key, indicator)
    return order, tables, str(doc.get("default") or "other")


@functools.lru_cache(maxsize=1)
def rule_cwes() -> dict[str, str]:
    """Rule id → CWE, from the coverage catalog; the rule output omits it."""
    doc = _load_yaml(_RULES_YAML)
    mapping: dict[str, str] = {}
    for family in ("hard_rules", "hypothesis_rules"):
        for rule in doc.get(family) or []:
            if isinstance(rule, dict) and rule.get("id") and rule.get("cwe"):
                mapping[str(rule["id"])] = str(rule["cwe"])
    return mapping


def indicator_for(
    cwes: list[str],
    scanner: str | None = None,
    check_id: str | None = None,
    iac_type: str | None = None,
) -> str:
    """Route one item to its indicator; see the catalog for the order.

    A config/IaC check is placed by its identity and family before its CWE is
    consulted, because that CWE describes the weakness in the pipeline, not the
    aspect of the application a reader is looking at.
    """
    _, tables, default = indicators()
    if check_id and check_id in tables["config_checks"]:
        return tables["config_checks"][check_id]
    if iac_type and iac_type in tables["iac_types"]:
        return tables["iac_types"][iac_type]
    normalized = [str(cwe or "").strip().upper() for cwe in cwes if cwe]
    for cwe in normalized:
        if cwe in tables["cwes"]:
            return tables["cwes"][cwe]
    for cwe in normalized:
        weakness_class = classify_cwe(cwe, warn=False)
        if weakness_class in tables["weakness_classes"]:
            return tables["weakness_classes"][weakness_class]
    return tables["scanners"].get(scanner or "", default)


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
        for finding in data.get("findings") or []:
            if isinstance(finding, dict):
                findings.append({**finding, "_scanner": label})

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


def finding_title(finding: dict) -> str:
    """The shortest phrasing of a finding that still reads correctly.

    A config/IaC finding carries the check *name*, which states the desired
    state ("package-lock.json present and committed") and would read as a pass.
    Its recommended mitigation is the authored phrasing that reads as an open
    item. A source finding states the weakness class before its first dash.
    """
    if finding.get("_scanner") == "config-iac":
        title = str(finding.get("recommended_mitigation_title") or finding.get("title") or "")
    else:
        title = str(finding.get("title") or "").split(" — ")[0]
    return title[:49] + "…" if len(title) > 50 else title


def top_findings(findings: list[dict], limit: int = TOP_FINDINGS) -> list[dict]:
    """The most severe distinct checks, each with one example location.

    Grouped by check rather than listed per hit: seventeen instances of one
    broken authorization check are one thing to fix, and listing them
    individually would fill the whole list with a single check.
    """
    order = list(SEVERITY_WEIGHT)
    groups: dict[str, dict[str, Any]] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "").strip().lower()
        if severity not in SEVERITY_WEIGHT:
            continue
        key = str(finding.get("check_id") or finding.get("title") or "?")
        group = groups.setdefault(key, {"count": 0, "severity": severity, "finding": finding})
        group["count"] += 1
        if order.index(severity) < order.index(group["severity"]):
            group["severity"], group["finding"] = severity, finding

    rows = [
        {
            "severity": group["severity"],
            "title": finding_title(group["finding"]),
            "count": group["count"],
            "location": _location(group["finding"]),
        }
        for group in groups.values()
    ]
    rows.sort(key=lambda row: (order.index(row["severity"]), -row["count"], row["title"]))
    return rows[:limit]


def _location(finding: dict) -> str:
    file = str(finding.get("file") or "?")
    line = finding.get("line")
    return f"{file}:{line}" if line else file


def rule_signal(rule: dict) -> str:
    """What one applicable rule actually saw, in the reader's words.

    The status alone does not distinguish "a control is in place" from "signals
    are there and nothing proves a control", which is the difference the row
    below the score has to carry.
    """
    decision = str(rule.get("decision") or "")
    if rule["status"] == "anti_pattern" or "threat_candidate" in decision or "anti_pattern" in decision:
        return "anti-pattern"
    if "hypothesis" in decision:
        return "hypothesis"
    return {
        "present": "control",
        "partial": "partial control",
        "weak": "weak control",
        "missing": "no control",
    }.get(rule["status"], rule["status"])


def rule_points(rule: dict) -> float:
    """Control credit for one applicable rule.

    The status alone overrates a rule that only raised a hypothesis. A repository
    whose sinks are all reached through unsanitized input scores ``partial`` on
    the injection rules, because the deterministic layer cannot prove the flow —
    proving it is the STRIDE stage's job. Half credit for that reads as "halfway
    controlled", which is the opposite of what the rule saw. The rule's decision
    therefore caps its credit: a hypothesis is not a control, and a threat
    candidate is a control that failed.
    """
    points = STATUS_POINTS[rule["status"]]
    return min(points, DECISION_CEILING.get(str(rule.get("decision") or ""), 1.0))


def _cwe_list(item: dict) -> list[str]:
    raw = item.get("cwe")
    return [str(c) for c in raw] if isinstance(raw, list) else [str(raw)] if raw else []


def finding_indicator(finding: dict) -> str:
    """Route one scanner finding to its indicator."""
    return indicator_for(
        _cwe_list(finding),
        scanner=finding.get("_scanner"),
        check_id=str(finding.get("check_id") or "") or None,
        iac_type=str(finding.get("iac_type") or "") or None,
    )


def _tally(findings: list[dict]) -> tuple[dict[str, int], float]:
    """Per-severity counts and the damped raw severity weight of a finding set."""
    counts = {severity: 0 for severity in SEVERITY_WEIGHT}
    per_check: dict[tuple[str, str], int] = collections.Counter()
    raw = 0.0
    for finding in findings:
        severity = str(finding.get("severity") or "").strip().lower()
        if severity not in SEVERITY_WEIGHT:
            continue
        counts[severity] += 1
        if finding.get("_scanner") in DAMPED_SCANNERS:
            per_check[(str(finding.get("check_id") or finding.get("title") or "?"), severity)] += 1
        else:
            raw += SEVERITY_WEIGHT[severity]
    raw += sum(SEVERITY_WEIGHT[severity] * (1 + math.log(n)) for (_, severity), n in per_check.items())
    return counts, raw


def finding_penalty(raw_weight: float) -> float:
    """Saturating deduction for a raw severity weight."""
    return PENALTY_CAP * raw_weight / (raw_weight + PENALTY_HALF_WEIGHT)


def compute(rules: list[dict], findings: list[dict]) -> dict[str, Any]:
    """Score the collected signals. Pure — no subprocesses, catalogs only.

    One score per security principle, from that principle's own rules and its
    own findings; the headline is their mean. A global penalty spread over the
    whole repository hid exactly what the breakdown is for — the category a
    repository actually fails in.
    """
    applicable = [r for r in rules if r.get("status") in STATUS_POINTS]
    counts, _ = _tally(findings)

    result: dict[str, Any] = {
        "checks_total": len(rules),
        "checks_applicable": len(applicable),
        "findings": counts,
        "findings_total": sum(counts.values()),
        "categories": [],
    }

    if len(applicable) < MIN_APPLICABLE_RULES:
        result["verdict"] = "undetermined"
        result["score"] = None
        result["reason"] = (
            f"only {len(applicable)} of {len(rules)} checks applied to this repository "
            f"({MIN_APPLICABLE_RULES} required) — the rule catalog does not cover it"
        )
        return result

    order, _, _ = indicators()
    cwe_by_rule = rule_cwes()
    buckets: dict[str, dict[str, Any]] = {
        indicator: {"points": [], "signals": [], "findings": []} for indicator, _ in order
    }

    def bucket_for(key: str) -> dict[str, Any]:
        return buckets.setdefault(key, {"points": [], "signals": [], "findings": []})

    for rule in applicable:
        cwe = cwe_by_rule.get(str(rule.get("rule_id") or ""))
        bucket = bucket_for(indicator_for([cwe] if cwe else []))
        bucket["points"].append(rule_points(rule))
        bucket["signals"].append(rule_signal(rule))
    for finding in findings:
        bucket_for(finding_indicator(finding))["findings"].append(finding)

    known = {indicator for indicator, _ in order}
    categories = []
    for indicator, label in [*order, *((key, key) for key in buckets if key not in known)]:
        bucket = buckets[indicator]
        points = bucket["points"]
        if not points and not bucket["findings"]:
            continue
        found_counts, raw = _tally(bucket["findings"])
        # An indicator no rule applied to has no control evidence. It still
        # shows its findings, but scoring it would mean scoring an absence.
        control = 100.0 * sum(points) / len(points) if points else None
        categories.append(
            {
                "indicator": indicator,
                "label": label,
                "score": None if control is None else max(0, round(control - finding_penalty(raw))),
                "checks": len(points),
                "signals": dict(collections.Counter(bucket["signals"])),
                "findings": sum(found_counts.values()),
                "severities": {k: v for k, v in found_counts.items() if v},
            }
        )

    categories.sort(key=lambda row: (row["score"] is None, row["score"], row["label"]))
    result["verdict"] = "scored"
    result["categories"] = categories

    # The weaker half decides. Averaging every category lets a well-covered area
    # pay for a broken one, which is not how a repository is attacked.
    scored = sorted(row["score"] for row in categories if row["score"] is not None)
    weaker_half = scored[: (len(scored) + 1) // 2]
    result["score"] = round(sum(weaker_half) / len(weaker_half))
    return result


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


# Plural forms for the rule signals; "hypothesis" is the one that needs it.
_PLURALS = {"hypothesis": "hypotheses", "anti-pattern": "anti-patterns"}


# Rides in the headline itself, where it cannot be cropped away from the number.
CAVEAT = "a limited quick check, not a full security analysis"

# One glyph vocabulary for both the scores and the severities, rather than ANSI
# colour: the skill reprints this block into Markdown, where escape sequences are
# either invisible or visible noise. The severity mapping is the one
# skills/authnz-review already prints.
_BANDS = ((25, "🔴"), (50, "🟠"), (75, "🟡"))
_UNSCORED_DOT = "⚪"
_SEVERITY_DOT = {"critical": "🔴", "high": "🟠", "medium": "🟡"}


def _dot(score: int | None) -> str:
    """Band glyph for a score. An unscored indicator gets the neutral one."""
    if score is None:
        return _UNSCORED_DOT
    for ceiling, glyph in _BANDS:
        if score < ceiling:
            return glyph
    return "🟢"


def _found(row: dict[str, Any]) -> str:
    """The findings half of an indicator line."""
    total = row.get("findings") or 0
    return "no findings" if not total else _count(total, "finding")


def _signals(row: dict[str, Any]) -> str:
    """The checks half of an indicator line."""
    signals = row.get("signals") or {}
    if not signals:
        return "no check applied"
    return ", ".join(
        f"{n} {_PLURALS.get(signal, signal) if n > 1 else signal}"
        for signal, n in sorted(signals.items(), key=lambda kv: (-kv[1], kv[0]))
    )


def render_text(result: dict[str, Any]) -> str:
    """The human-readable report: a headline, the categories, then the caveats.

    The qualifiers ride in the second line rather than in a closing paragraph —
    the number must not travel without them, and prose would be skipped anyway.
    """
    counts = result["findings"]
    scan = f"{result['checks_applicable']} of {result['checks_total']} checks applied · no exposure context"

    if result["verdict"] == "undetermined":
        return f"{_UNSCORED_DOT} Security Score  undetermined — {CAVEAT}\n{result['reason']}"

    lines = [f"{_dot(result['score'])} Security Score  {result['score']} / 100 — {CAVEAT}", scan, ""]

    width = max((len(row["label"]) for row in result["categories"]), default=0)
    found_width = max((len(_found(row)) for row in result["categories"]), default=0)
    for row in result["categories"]:
        score = "no check" if row["score"] is None else f"{row['score']:>3}/100"
        lines.append(
            f"  {_dot(row['score'])} {score:>8}  {row['label']:<{width}}"
            f"  {_found(row):>{found_width}} · {_signals(row)}"
        )

    lines += [
        "",
        f"  {counts['critical']} critical · {counts['high']} high · {counts['medium']} medium",
    ]

    top = result.get("top_findings") or []
    if top:
        lines += ["", "  most severe findings"]
        width = max(len(row["title"]) for row in top)
        for row in top:
            seen = f"{row['count']}×" if row["count"] > 1 else ""
            dot = _SEVERITY_DOT.get(row["severity"], _UNSCORED_DOT)
            lines.append(f"  {dot} {row['title']:<{width}}  {seen:>4}  {row['location']}")

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
    result["top_findings"] = top_findings(findings)
    result["repo"] = str(repo_root)
    result["warnings"] = warnings

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_text(result))

    return 2 if result["verdict"] == "undetermined" else 0


if __name__ == "__main__":
    sys.exit(main())
