#!/usr/bin/env python3
"""
architecture_coverage_checks.py — deterministic architecture-coverage engine.

Always-on evaluation of problematic security controls and architecture
anti-patterns. Reads:
  * data/architecture-coverage-rules.yaml          — rule catalog (required)
  * $OUTPUT_DIR/.route-inventory.json              — route basis (optional)
  * $OUTPUT_DIR/.recon-patterns.json               — recon signals (optional)
  * $OUTPUT_DIR/.config-scan-findings.json         — config/IaC signals (optional)

Writes:
  $OUTPUT_DIR/.architecture-coverage.json  conforming to
  schemas/architecture-coverage.schema.json.

Contract (arch.md §Erste Lieferung):
  * Every rule appears in rules_evaluated[] — not just matches.
  * The unknown-is-not-absent gate: route signals 'unknown' / 'inherited_unknown'
    never escalate to a hard candidate on their own.
  * Hard candidates require positive evidence; absence of an exculpatory
    framework is not enough.
  * Hypothesis rules default to emit_hypothesis_only; promotion to a
    threat candidate requires proof_state=confirmed (currently emitted
    only when a positive signal AND an inventory surface co-occur and
    no exculpatory signal is present in the same file).

CLI:
    python3 scripts/architecture_coverage_checks.py \
        --repo-root <repo> --output-dir <dir>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import yaml
except ImportError:  # pragma: no cover
    print("architecture_coverage_checks.py: PyYAML is required", file=sys.stderr)
    sys.exit(1)

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
try:
    from scan_excludes import is_excluded as _scan_is_excluded  # type: ignore
except Exception:  # pragma: no cover
    _scan_is_excluded = None


_DEFAULT_RULES_YAML = _HERE.parent / "data" / "architecture-coverage-rules.yaml"

_SOURCE_EXTS = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".py",
    ".java", ".kt", ".scala",
    ".cs", ".vb",
    ".go", ".rb", ".php",
    ".yaml", ".yml", ".json", ".toml", ".conf", ".env",
    ".properties",
    ".cfg", ".ini",
}


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _is_excluded(rel: str) -> bool:
    if _scan_is_excluded is not None:
        try:
            return bool(_scan_is_excluded(rel))
        except Exception:  # pragma: no cover
            pass
    parts = rel.split("/")
    return any(p in {"node_modules", ".git", "dist", "build", "vendor", "target", "out", ".venv", "venv"} for p in parts)


def _walk_sources(repo_root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(repo_root):
        rel_dir = str(Path(dirpath).relative_to(repo_root)).replace("\\", "/")
        dirnames[:] = [d for d in dirnames if not _is_excluded(f"{rel_dir}/{d}" if rel_dir != "." else d)]
        for name in filenames:
            rel = str((Path(dirpath) / name).relative_to(repo_root)).replace("\\", "/")
            if _is_excluded(rel):
                continue
            p = Path(dirpath) / name
            if p.suffix.lower() not in _SOURCE_EXTS:
                continue
            yield p


def _read_lines(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def _load_json_or_none(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _plugin_data_file(env_var: str, default: Path, filename: str) -> Path:
    override = os.environ.get(env_var)
    if override:
        return Path(override)
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if plugin_root:
        cand = Path(plugin_root) / "data" / filename
        if cand.is_file():
            return cand
    return default


def _load_rules(path: Path | None = None) -> dict:
    path = path or _plugin_data_file("ARCH_COVERAGE_RULES_YAML", _DEFAULT_RULES_YAML, "architecture-coverage-rules.yaml")
    if not path.is_file():
        raise FileNotFoundError(f"architecture-coverage-rules.yaml not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise ValueError(f"{path}: unsupported version {data.get('version')!r}")
    return data


def _with_arch_fields(base: dict, rule: "CompiledRule") -> dict:
    enriched = dict(base)
    if rule.architectural_theme:
        enriched["architectural_theme"] = rule.architectural_theme
    if rule.generic_threat_title:
        enriched["generic_threat_title"] = rule.generic_threat_title
    return enriched


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    control: str
    domain: str
    cwe: str
    threat_category_id: str
    stride: str
    severity_cap: str
    output: str
    family: str  # "hard" | "hypothesis"
    hypothesis_id_prefix: str | None
    architectural_theme: str | None
    generic_threat_title: str | None
    weak_or_missing_controls: list[str]
    precondition_patterns: list[re.Pattern[str]]
    positive_patterns: list[re.Pattern[str]]
    cooccurrence_patterns: list[re.Pattern[str]]
    cooccurrence_window: int
    exculpatory_patterns: list[re.Pattern[str]]
    route_inventory_required: bool
    requires_management_surface: bool
    route_requires: dict
    forbidden_route_signals: dict
    inventory_pattern: dict


def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    out: list[re.Pattern[str]] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error as e:  # pragma: no cover
            print(f"architecture_coverage_checks.py: bad regex {p!r}: {e}", file=sys.stderr)
    return out


def _compile_rule(rule: dict, family: str) -> CompiledRule:
    precondition_patterns: list[re.Pattern[str]] = []
    route_inventory_required = False
    requires_management_surface = False
    for pre in rule.get("preconditions", []) or []:
        kind = pre.get("kind")
        if kind == "code_signal":
            precondition_patterns.extend(_compile_patterns(pre.get("any_pattern", []) or []))
        elif kind == "route_inventory_signal":
            route_inventory_required = True
            if pre.get("require_route_signal") == "management_surface":
                requires_management_surface = True
        # any_of_signals currently treated as informational (engine handles in evaluator).

    pos_block = rule.get("positive_signals", {}) or {}
    positive_patterns = _compile_patterns(pos_block.get("any_pattern", []) or [])
    cooccurrence_patterns = _compile_patterns(pos_block.get("cooccurrence_pattern", []) or [])
    cooccurrence_window = int(pos_block.get("requires_cooccurrence_window", 0) or 0)
    route_requires = pos_block.get("route_requires", {}) or {}
    forbidden_route_signals = pos_block.get("forbidden_route_signals", {}) or {}
    inventory_pattern = pos_block.get("inventory_pattern", {}) or {}

    exc_block = rule.get("exculpatory_signals", {}) or {}
    exculpatory_patterns = _compile_patterns(exc_block.get("any_pattern", []) or [])

    return CompiledRule(
        rule_id=rule["id"],
        title=rule["title"],
        control=rule["control"],
        domain=rule["domain"],
        cwe=rule["cwe"],
        threat_category_id=rule["threat_category_id"],
        stride=rule["stride"],
        severity_cap=rule.get("severity_cap", "Medium"),
        output=rule.get("output", "control_assessment"),
        family=family,
        hypothesis_id_prefix=rule.get("hypothesis_id_prefix"),
        architectural_theme=rule.get("architectural_theme"),
        generic_threat_title=rule.get("generic_threat_title"),
        weak_or_missing_controls=list(rule.get("weak_or_missing_controls", []) or []),
        precondition_patterns=precondition_patterns,
        positive_patterns=positive_patterns,
        cooccurrence_patterns=cooccurrence_patterns,
        cooccurrence_window=cooccurrence_window,
        exculpatory_patterns=exculpatory_patterns,
        route_inventory_required=route_inventory_required,
        requires_management_surface=requires_management_surface,
        route_requires=route_requires,
        forbidden_route_signals=forbidden_route_signals,
        inventory_pattern=inventory_pattern,
    )


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


@dataclass
class PatternHits:
    precondition: list[tuple[str, int, str]] = field(default_factory=list)
    positive: list[tuple[str, int, str]] = field(default_factory=list)
    cooccurrence: list[tuple[str, int, str]] = field(default_factory=list)
    exculpatory: list[tuple[str, int, str]] = field(default_factory=list)


def _scan_file_for_rule(rel: str, lines: list[str], rule: CompiledRule) -> PatternHits:
    hits = PatternHits()
    for n, line in enumerate(lines, start=1):
        stripped = line.rstrip("\r\n")
        if len(stripped) > 400:
            stripped = stripped[:400]
        for pat in rule.precondition_patterns:
            if pat.search(line):
                hits.precondition.append((rel, n, stripped))
                break
        exculpatory_match = False
        for pat in rule.exculpatory_patterns:
            if pat.search(line):
                hits.exculpatory.append((rel, n, stripped))
                exculpatory_match = True
                break
        if not exculpatory_match:
            for pat in rule.positive_patterns:
                if pat.search(line):
                    hits.positive.append((rel, n, stripped))
                    break
        for pat in rule.cooccurrence_patterns:
            if pat.search(line):
                hits.cooccurrence.append((rel, n, stripped))
                break
    return hits


def _cooccurrence_satisfied(hits: PatternHits, window: int) -> list[tuple[str, int, str]]:
    """Return the subset of positive hits whose line is within +/- window
    lines of a cooccurrence hit in the same file."""
    if window <= 0 or not hits.cooccurrence:
        return hits.positive[:]
    matched: list[tuple[str, int, str]] = []
    by_file: dict[str, list[int]] = {}
    for f, ln, _ in hits.cooccurrence:
        by_file.setdefault(f, []).append(ln)
    for f, ln, txt in hits.positive:
        candidates = by_file.get(f, [])
        if any(abs(ln - c) <= window for c in candidates):
            matched.append((f, ln, txt))
    return matched


# ---------------------------------------------------------------------------
# Rule-specific route-inventory checks (ARCH-MGMT-001, ARCH-AUTHZ-001)
# ---------------------------------------------------------------------------


def _evaluate_mgmt_rule(rule: CompiledRule, inventory: dict | None) -> dict:
    """Returns {applies, status, confidence, evidence, skip_reason}.

    arch.md §ARCH-MGMT-001:
      hard candidate only when management_surface=true AND authn_signal=absent AND
      authz_signal=absent. 'unknown' / 'inherited_unknown' must NOT escalate.
    """
    if not inventory:
        return {
            "applies": False,
            "status": "not_applicable",
            "confidence": "low",
            "evidence": [],
            "skip_reason": ".route-inventory.json not available",
        }

    routes = inventory.get("routes", [])
    mgmt_routes = [r for r in routes if r.get("management_surface")]
    if not mgmt_routes:
        return {
            "applies": False,
            "status": "not_applicable",
            "confidence": "low",
            "evidence": [],
            "skip_reason": "no management surface in route inventory",
        }

    require = rule.route_requires or {}
    authn_in = set(require.get("authn_signal_in", ["absent"]))
    authz_in = set(require.get("authz_signal_in", ["absent"]))
    forbid_authn = set((rule.forbidden_route_signals or {}).get("authn_signal", []))

    evidence: list[dict] = []
    for r in mgmt_routes:
        if r.get("authn_signal") in forbid_authn:
            continue
        if r.get("authn_signal") in authn_in and r.get("authz_signal") in authz_in:
            evidence.append({
                "file": r.get("handler_file", ""),
                "line": int(r.get("handler_line", 1)),
                "signal": f"management surface {r.get('method')} {r.get('path')} authn={r.get('authn_signal')} authz={r.get('authz_signal')}",
            })

    if evidence:
        return {
            "applies": True,
            "status": "weak",  # default; not anti_pattern unless engine sees further evidence
            "confidence": "medium",
            "evidence": evidence,
            "skip_reason": None,
        }

    weak_evidence: list[dict] = []
    for r in mgmt_routes:
        if r.get("authn_signal") in {"unknown", "inherited_unknown"}:
            weak_evidence.append({
                "file": r.get("handler_file", ""),
                "line": int(r.get("handler_line", 1)),
                "signal": f"management surface {r.get('method')} {r.get('path')} authn={r.get('authn_signal')} — unknown does not escalate",
            })
    return {
        "applies": True,
        "status": "partial" if weak_evidence else "present",
        "confidence": "low",
        "evidence": weak_evidence,
        "skip_reason": None if weak_evidence else "management routes carry positive auth signals",
    }


def _evaluate_authz_hyp_rule(rule: CompiledRule, inventory: dict | None) -> dict:
    """Hypothesis-only evaluation against inventory: sensitive methods
    (DELETE/PUT/PATCH) with no authz signal."""
    if not inventory:
        return {"applies": False, "status": "not_applicable", "confidence": "low",
                "evidence": [], "skip_reason": ".route-inventory.json not available"}
    pat = rule.inventory_pattern or {}
    methods = set(pat.get("sensitive_methods", []) or [])
    authz_states = set(pat.get("require_authz_signal_in", ["absent", "unknown"]))
    min_n = int(pat.get("min_routes", 1) or 1)
    if not methods:
        return {"applies": False, "status": "not_applicable", "confidence": "low",
                "evidence": [], "skip_reason": "no inventory_pattern.sensitive_methods configured"}

    routes = inventory.get("routes", [])
    matches: list[dict] = []
    has_authenticated = False
    for r in routes:
        if r.get("authn_signal") in {"present", "middleware_present", "decorator_present"}:
            has_authenticated = True
        if r.get("method") in methods and r.get("authz_signal") in authz_states:
            matches.append({
                "file": r.get("handler_file", ""),
                "line": int(r.get("handler_line", 1)),
                "signal": f"sensitive method {r.get('method')} {r.get('path')} authz={r.get('authz_signal')}",
            })

    if not has_authenticated:
        return {
            "applies": False, "status": "not_applicable", "confidence": "low",
            "evidence": [],
            "skip_reason": "no authenticated routes — precondition not met",
        }

    if len(matches) < min_n:
        return {
            "applies": True, "status": "present", "confidence": "low",
            "evidence": [],
            "skip_reason": None,
        }

    return {
        "applies": True,
        "status": "weak",
        "confidence": "medium",
        "evidence": matches,
        "skip_reason": None,
    }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _aggregate_hits_for_rule(repo_root: Path, rule: CompiledRule) -> PatternHits:
    agg = PatternHits()
    for src in _walk_sources(repo_root):
        rel = str(src.relative_to(repo_root)).replace("\\", "/")
        lines = _read_lines(src)
        if not lines:
            continue
        hits = _scan_file_for_rule(rel, lines, rule)
        agg.precondition.extend(hits.precondition)
        agg.positive.extend(hits.positive)
        agg.cooccurrence.extend(hits.cooccurrence)
        agg.exculpatory.extend(hits.exculpatory)
    return agg


def _evidence_dicts(items: list[tuple[str, int, str]], cap: int = 8) -> list[dict]:
    out: list[dict] = []
    for f, ln, txt in items[:cap]:
        out.append({"file": f, "line": int(ln), "signal": txt.strip()})
    return out


def _evaluate_hard_rule(rule: CompiledRule, repo_root: Path, inventory: dict | None) -> dict:
    if rule.rule_id == "ARCH-MGMT-001":
        return _evaluate_mgmt_rule(rule, inventory)

    hits = _aggregate_hits_for_rule(repo_root, rule)
    if rule.precondition_patterns and not hits.precondition:
        return {
            "applies": False, "status": "not_applicable", "confidence": "low",
            "evidence": [], "skip_reason": "no precondition signal in repo",
        }

    if rule.cooccurrence_window > 0 or rule.cooccurrence_patterns:
        effective_positive = _cooccurrence_satisfied(hits, rule.cooccurrence_window)
    else:
        effective_positive = hits.positive

    if not effective_positive:
        if hits.exculpatory:
            return {
                "applies": True, "status": "present", "confidence": "medium",
                "evidence": _evidence_dicts(hits.exculpatory[:2]),
                "skip_reason": None,
            }
        return {
            "applies": True, "status": "partial", "confidence": "low",
            "evidence": [],
            "skip_reason": "preconditions present but no positive/exculpatory signal",
        }

    status = "anti_pattern" if rule.output == "anti_pattern_candidate" else "weak"
    confidence = "high" if not hits.exculpatory else "medium"
    if hits.exculpatory and status == "anti_pattern":
        status = "weak"

    return {
        "applies": True, "status": status, "confidence": confidence,
        "evidence": _evidence_dicts(effective_positive),
        "skip_reason": None,
    }


def _evaluate_hypothesis_rule(rule: CompiledRule, repo_root: Path, inventory: dict | None) -> dict:
    if rule.rule_id == "ARCH-AUTHZ-001":
        return _evaluate_authz_hyp_rule(rule, inventory)

    hits = _aggregate_hits_for_rule(repo_root, rule)
    if rule.precondition_patterns and not hits.precondition:
        return {
            "applies": False, "status": "not_applicable", "confidence": "low",
            "evidence": [], "skip_reason": "no precondition signal in repo",
        }

    if not hits.positive:
        if hits.exculpatory:
            return {
                "applies": True, "status": "present", "confidence": "medium",
                "evidence": _evidence_dicts(hits.exculpatory[:2]),
                "skip_reason": None,
            }
        return {
            "applies": True, "status": "partial", "confidence": "low",
            "evidence": [],
            "skip_reason": "preconditions present but no positive signal",
        }

    confidence = "medium"
    status = "weak"
    if hits.exculpatory:
        confidence = "low"
        status = "partial"

    return {
        "applies": True, "status": status, "confidence": confidence,
        "evidence": _evidence_dicts(hits.positive),
        "skip_reason": None,
    }


# ---------------------------------------------------------------------------
# Decision mapping
# ---------------------------------------------------------------------------


def _decision_for_hard(rule: CompiledRule, verdict: dict) -> str:
    if not verdict["applies"]:
        return "no_action"
    status = verdict["status"]
    if status == "present":
        return "emit_control_only"
    if status == "anti_pattern":
        return "emit_control_and_threat_candidate" if rule.output == "anti_pattern_candidate" else "emit_anti_pattern_candidate"
    if status in {"partial", "weak", "missing"}:
        return "emit_control_only"
    return "no_action"


def _decision_for_hypothesis(rule: CompiledRule, verdict: dict) -> str:
    if not verdict["applies"]:
        return "no_action"
    if verdict["status"] in {"present", "not_applicable"}:
        return "emit_control_only"
    if rule.output == "control_and_hypothesis":
        return "emit_control_and_hypothesis"
    return "emit_hypothesis_only"


# ---------------------------------------------------------------------------
# Top-level run
# ---------------------------------------------------------------------------


def run(repo_root: Path, output_dir: Path | None, rules_data: dict) -> dict:
    inventory: dict | None = None
    if output_dir is not None:
        inventory = _load_json_or_none(output_dir / ".route-inventory.json")

    rules_evaluated: list[dict] = []
    control_assessments: list[dict] = []
    anti_patterns: list[dict] = []
    hypotheses: list[dict] = []
    warnings: list[str] = []

    hyp_counter: dict[str, int] = {}

    for rule_dict in rules_data.get("hard_rules", []) or []:
        rule = _compile_rule(rule_dict, "hard")
        verdict = _evaluate_hard_rule(rule, repo_root, inventory)
        decision = _decision_for_hard(rule, verdict)
        rules_evaluated.append(_with_arch_fields({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "status": verdict["status"],
            "applies": verdict["applies"],
            "confidence": verdict["confidence"],
            "control": rule.control,
            "domain": rule.domain,
            "evidence": verdict["evidence"],
            "skip_reason": verdict.get("skip_reason"),
            "decision": decision,
        }, rule))

        if verdict["status"] in {"partial", "weak", "missing", "anti_pattern"} and verdict["applies"]:
            control_assessments.append(_with_arch_fields({
                "rule_id": rule.rule_id,
                "control": rule.control,
                "domain": rule.domain,
                "status": verdict["status"],
                "confidence": verdict["confidence"],
                "evidence": verdict["evidence"],
                "hypothesis_ids": [],
            }, rule))

        if (
            rule.output == "anti_pattern_candidate"
            and verdict["status"] == "anti_pattern"
            and verdict["confidence"] == "high"
            and verdict["evidence"]
        ):
            anti_patterns.append(_with_arch_fields({
                "rule_id": rule.rule_id,
                "title": rule.title,
                "cwe": rule.cwe,
                "domain": rule.domain,
                "severity_cap": rule.severity_cap,
                "evidence": verdict["evidence"],
                "confidence": verdict["confidence"],
                "must_not_carry_cvss": True,
            }, rule))

    for rule_dict in rules_data.get("hypothesis_rules", []) or []:
        rule = _compile_rule(rule_dict, "hypothesis")
        verdict = _evaluate_hypothesis_rule(rule, repo_root, inventory)
        decision = _decision_for_hypothesis(rule, verdict)

        rules_evaluated.append(_with_arch_fields({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "status": verdict["status"],
            "applies": verdict["applies"],
            "confidence": verdict["confidence"],
            "control": rule.control,
            "domain": rule.domain,
            "evidence": verdict["evidence"],
            "skip_reason": verdict.get("skip_reason"),
            "decision": decision,
        }, rule))

        if verdict["applies"] and verdict["status"] not in {"present", "not_applicable"}:
            hyp_counter.setdefault(rule.hypothesis_id_prefix or "ARCH-HYP-GEN", 0)
            hyp_counter[rule.hypothesis_id_prefix or "ARCH-HYP-GEN"] += 1
            idx = hyp_counter[rule.hypothesis_id_prefix or "ARCH-HYP-GEN"]
            hyp_id = f"{rule.hypothesis_id_prefix}-{idx:03d}"

            hypotheses.append(_with_arch_fields({
                "hypothesis_id": hyp_id,
                "rule_id": rule.rule_id,
                "title": rule.title,
                "threat_category_id": rule.threat_category_id,
                "stride": rule.stride,
                "cwe": rule.cwe,
                "component_id": None,
                "domain": rule.domain,
                "surface": None,
                "proof_state": "control-derived",
                "confidence": verdict["confidence"],
                "weak_or_missing_controls": rule.weak_or_missing_controls,
                "positive_signals": verdict["evidence"],
                "negative_signals": [],
                "exculpatory_signals": [],
                "decision": "emit_hypothesis_only",
            }, rule))

            if rule.output == "control_and_hypothesis":
                control_assessments.append(_with_arch_fields({
                    "rule_id": rule.rule_id,
                    "control": rule.control,
                    "domain": rule.domain,
                    "status": "partial",
                    "confidence": verdict["confidence"],
                    "evidence": verdict["evidence"],
                    "hypothesis_ids": [hyp_id],
                }, rule))

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(repo_root),
        "rules_evaluated": rules_evaluated,
        "control_assessments": control_assessments,
        "threat_hypotheses": hypotheses,
        "anti_pattern_candidates": anti_patterns,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="architecture_coverage_checks.py", description=__doc__)
    p.add_argument("--repo-root", required=True)
    p.add_argument("--output-dir", help="If provided, writes .architecture-coverage.json there.")
    p.add_argument("--rules-yaml", help="Override path to architecture-coverage-rules.yaml.")
    p.add_argument("--stdout", action="store_true")
    args = p.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"architecture_coverage_checks.py: repo-root not found: {repo_root}", file=sys.stderr)
        return 1
    output_dir = Path(args.output_dir) if args.output_dir else None

    rules = _load_rules(Path(args.rules_yaml) if args.rules_yaml else None)
    result = run(repo_root, output_dir, rules)

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / ".architecture-coverage.json"
        out_path.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        if not args.stdout:
            print(str(out_path))

    if args.stdout or output_dir is None:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
