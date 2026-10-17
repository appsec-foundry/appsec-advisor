#!/usr/bin/env python3
"""
analyzers/architecture_coverage_checks.py — deterministic architecture-coverage engine.

Always-on evaluation of problematic security controls and architecture
anti-patterns. Reads:
  * data/architecture-coverage-rules.yaml          — rule catalog (required)
  * repository source files under --repo-root      — rule signal patterns
  * $OUTPUT_DIR/.route-inventory.json              — route basis (optional)
  * $OUTPUT_DIR/.db-privilege-separation.json      — DB principal separation
                                                     (optional, thorough only)

Writes:
  $OUTPUT_DIR/.architecture-coverage.json  conforming to
  schemas/architecture-coverage.schema.json.

Contract:
  * Every rule appears in rules_evaluated[] — not just matches.
  * The unknown-is-not-absent gate: route signals 'unknown' / 'inherited_unknown'
    never escalate to a hard candidate on their own.
  * Hard candidates require positive evidence; absence of an exculpatory
    framework is not enough.
  * Hypothesis rules default to emit_hypothesis_only; promotion to a
    threat candidate requires proof_state=confirmed, which only confirmed
    records in .db-privilege-separation.json produce.

CLI:
    python3 scripts/analyzers/architecture_coverage_checks.py \
        --repo-root <repo> --output-dir <dir>
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from shared._path_guard import is_safe_to_read

try:
    import yaml
except ImportError:  # pragma: no cover
    print("analyzers/architecture_coverage_checks.py: PyYAML is required", file=sys.stderr)
    sys.exit(1)

_HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_HERE))
try:
    from analyzers.scan_excludes import is_excluded as _scan_is_excluded  # type: ignore
except Exception:  # pragma: no cover
    _scan_is_excluded = None
try:
    from analyzers.scan_excludes import is_assessment_artifact as _scan_is_assessment_artifact  # type: ignore
except Exception:  # pragma: no cover
    _scan_is_assessment_artifact = None


_DEFAULT_RULES_YAML = _HERE.parent / "data" / "architecture-coverage-rules.yaml"


# Engine-wide default excludes. Any path containing one of these
# segments is never scanned, regardless of how permissive a rule's signal
# patterns are. This prevents future repo-wide rules (e.g. `**/*.ts`) from
# walking into bundled vendor code and producing spurious anti-pattern matches.
#
# Opt-out: set the environment variable ``APPSEC_ARCH_INCLUDE_VENDOR=1`` for
# specialised audits (e.g. lockfile or supply-chain scans that explicitly
# need to inspect vendored sources). NEVER use this opt-out for normal
# architecture-coverage runs.
_DEFAULT_EXCLUDES = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        "vendor",
        "target",
        "out",
        ".venv",
        "venv",
        ".next",
        "__pycache__",
    }
)

_SOURCE_EXTS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".java",
    ".kt",
    ".scala",
    ".cs",
    ".vb",
    ".go",
    ".rb",
    ".php",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".conf",
    ".env",
    ".properties",
    ".cfg",
    ".ini",
}


# Stored-XSS confirmation is deliberately narrower than the generic XSS
# hypothesis. A raw HTML sink alone says nothing about where its data came
# from. We only emit ARCH-XSS-002 when one source line explicitly maps a
# request field into a persistence call and a separate unsafe HTML sink renders
# that exact persisted property without a sanitizer on the sink line.
_REQUEST_FIELD_ASSIGNMENT = re.compile(
    r"(?i)(?:(?P<property>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*)?"
    r"(?:req|request)\.(?:body|json)\.(?P<input>[A-Za-z_][A-Za-z0-9_]*)"
)
_PERSISTENCE_MODEL_CALL = re.compile(
    r"(?i)\b(?P<model>[A-Za-z_][A-Za-z0-9_]*)\.(?:create|insert(?:One|Many)?|save|update|upsert|persist)\s*\("
)
_UNSAFE_HTML_SINK = re.compile(
    r"(?i)(?:\.innerHTML\s*=|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML|"
    r"bypassSecurityTrustHtml\s*\(|\bv-html\b|\{@html\b)"
)
_SINK_SANITIZER = re.compile(r"(?i)(?:DOMPurify\.sanitize|sanitize\s*\(|escapeHtml\s*\()")

# Evidence stays reviewable: a cited source line is cut to this many
# characters, and a verdict cites at most this many locations.
_MAX_SIGNAL_CHARS = 400
_MAX_EVIDENCE_ITEMS = 8


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _is_excluded(rel: str, repo_root: Path | None = None) -> bool:
    # Opt-out for specialised audits (lockfile / supply chain).
    if os.environ.get("APPSEC_ARCH_INCLUDE_VENDOR") == "1":
        return False
    if _scan_is_excluded is not None:
        try:
            if _scan_is_excluded(rel):
                return True
        except Exception:  # pragma: no cover
            pass
    # A prior run's output committed under any name is not source evidence.
    # `is_excluded` only knows the fixed `docs/security/` prefix, so a copied,
    # renamed or A/B-compared output directory walks straight back in and the
    # engine cites its own earlier verdicts as if they were code. Detect those
    # directories by their on-disk signature instead of their name.
    if repo_root is not None and _scan_is_assessment_artifact is not None:
        try:
            if _scan_is_assessment_artifact(rel, repo_root):
                return True
        except Exception:  # pragma: no cover
            pass
    parts = rel.split("/")
    return any(p in _DEFAULT_EXCLUDES for p in parts)


def _walk_sources(repo_root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(repo_root):
        rel_dir = str(Path(dirpath).relative_to(repo_root)).replace("\\", "/")
        dirnames[:] = [d for d in dirnames if not _is_excluded(f"{rel_dir}/{d}" if rel_dir != "." else d, repo_root)]
        for name in filenames:
            rel = str((Path(dirpath) / name).relative_to(repo_root)).replace("\\", "/")
            if _is_excluded(rel, repo_root):
                continue
            p = Path(dirpath) / name
            if p.suffix.lower() not in _SOURCE_EXTS:
                continue
            if is_safe_to_read(p, repo_root):
                yield p


def _read_lines(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


# The architecture rules share one repository-wide source view.  Keeping the
# decoded lines lets each rule retain its own matching semantics without
# repeatedly traversing and opening the exact same source tree.
SourceSnapshot = list[tuple[str, list[str]]]


def _load_source_snapshot(repo_root: Path) -> SourceSnapshot:
    snapshot: SourceSnapshot = []
    for src in _walk_sources(repo_root):
        lines = _read_lines(src)
        if not lines:
            continue
        rel = str(src.relative_to(repo_root)).replace("\\", "/")
        snapshot.append((rel, lines))
    return snapshot


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
    path = path or _plugin_data_file(
        "ARCH_COVERAGE_RULES_YAML", _DEFAULT_RULES_YAML, "architecture-coverage-rules.yaml"
    )
    if not path.is_file():
        raise FileNotFoundError(f"architecture-coverage-rules.yaml not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise ValueError(f"{path}: unsupported version {data.get('version')!r}")
    return data


def _with_arch_fields(base: dict, rule: CompiledRule) -> dict:
    enriched = dict(base)
    if rule.architectural_theme:
        enriched["architectural_theme"] = rule.architectural_theme
    if rule.generic_threat_title:
        enriched["generic_threat_title"] = rule.generic_threat_title
    if rule.weakness_mechanism:
        enriched["weakness_mechanism"] = rule.weakness_mechanism
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
    hypothesis_id_prefix: str | None
    architectural_theme: str | None
    generic_threat_title: str | None
    weak_or_missing_controls: list[str]
    precondition_patterns: list[re.Pattern[str]]
    positive_patterns: list[re.Pattern[str]]
    cooccurrence_patterns: list[re.Pattern[str]]
    cooccurrence_window: int
    exculpatory_patterns: list[re.Pattern[str]]
    route_requires: dict
    forbidden_route_signals: dict
    inventory_pattern: dict
    weakness_mechanism: str | None = None


def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    out: list[re.Pattern[str]] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error as e:  # pragma: no cover
            print(f"analyzers/architecture_coverage_checks.py: bad regex {p!r}: {e}", file=sys.stderr)
    return out


def _compile_rule(rule: dict) -> CompiledRule:
    # Only `code_signal` preconditions gate the generic evaluator. Other kinds
    # (route_inventory_signal, any_of_signals) document the rule for readers;
    # the rule-specific evaluators check the route inventory themselves.
    precondition_patterns: list[re.Pattern[str]] = []
    for pre in rule.get("preconditions", []) or []:
        if pre.get("kind") == "code_signal":
            precondition_patterns.extend(_compile_patterns(pre.get("any_pattern", []) or []))

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
        hypothesis_id_prefix=rule.get("hypothesis_id_prefix"),
        architectural_theme=rule.get("architectural_theme"),
        generic_threat_title=rule.get("generic_threat_title"),
        weakness_mechanism=rule.get("weakness_mechanism"),
        weak_or_missing_controls=list(rule.get("weak_or_missing_controls", []) or []),
        precondition_patterns=precondition_patterns,
        positive_patterns=positive_patterns,
        cooccurrence_patterns=cooccurrence_patterns,
        cooccurrence_window=cooccurrence_window,
        exculpatory_patterns=exculpatory_patterns,
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
    """Collect every line that matches one of the rule's four pattern groups.

    A line that matches an exculpatory pattern never counts as a positive hit:
    the safe form on the same line wins over the unsafe one.
    """
    hits = PatternHits()
    for n, line in enumerate(lines, start=1):
        stripped = line.rstrip("\r\n")[:_MAX_SIGNAL_CHARS]
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
    lines of a cooccurrence hit in the same file. Without any cooccurrence hit
    no positive hit qualifies; a window of 0 disables the requirement."""
    if window <= 0:
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
# Verdicts
# ---------------------------------------------------------------------------
#
# Every evaluator returns one verdict with the same keys:
#   applies      whether the rule's surface exists in this repository
#   status       not_applicable | present | partial | weak | anti_pattern
#   confidence   low | medium | high
#   evidence     up to _MAX_EVIDENCE_ITEMS {file, line, signal} locations
#   skip_reason  why the rule did not fire, or None
# Some verdicts add `proof_state` for the hypothesis they seed.


def _verdict(
    status: str,
    confidence: str,
    evidence: list[dict] | None = None,
    skip_reason: str | None = None,
    *,
    applies: bool = True,
    **extra: str,
) -> dict:
    return {
        "applies": applies,
        "status": status,
        "confidence": confidence,
        "evidence": evidence or [],
        "skip_reason": skip_reason,
        **extra,
    }


def _not_applicable(reason: str) -> dict:
    return _verdict("not_applicable", "low", skip_reason=reason, applies=False)


def _route_evidence(route: dict, signal: str) -> dict:
    """Cite a route-inventory entry by its handler location."""
    return {"file": route.get("handler_file", ""), "line": int(route.get("handler_line", 1)), "signal": signal}


def _evidence_dicts(items: list[tuple[str, int, str]], cap: int = _MAX_EVIDENCE_ITEMS) -> list[dict]:
    return [{"file": f, "line": int(ln), "signal": txt.strip()} for f, ln, txt in items[:cap]]


# ---------------------------------------------------------------------------
# Rule-specific route-inventory checks (ARCH-MGMT-001, ARCH-AUTHZ-001)
# ---------------------------------------------------------------------------
#
# These rules read `.route-inventory.json` instead of source lines. An
# authentication or authorization signal of `unknown` / `inherited_unknown`
# means the inventory could not see a check, not that the check is missing,
# so it never escalates on its own.

_NO_INVENTORY = ".route-inventory.json not available"


def _evaluate_mgmt_rule(rule: CompiledRule, inventory: dict | None) -> dict:
    """ARCH-MGMT-001: management routes without authentication or authorization.

    The rule fires (status weak) only for management routes whose authn and
    authz signals both fall in the rule's `route_requires` sets (default
    `absent`). Routes with an unknown authn signal make the control partial.
    """
    if not inventory:
        return _not_applicable(_NO_INVENTORY)

    mgmt_routes = [r for r in inventory.get("routes", []) if r.get("management_surface")]
    if not mgmt_routes:
        return _not_applicable("no management surface in route inventory")

    require = rule.route_requires or {}
    authn_in = set(require.get("authn_signal_in", ["absent"]))
    authz_in = set(require.get("authz_signal_in", ["absent"]))
    forbid_authn = set((rule.forbidden_route_signals or {}).get("authn_signal", []))

    evidence = [
        _route_evidence(
            r,
            f"management surface {r.get('method')} {r.get('path')} "
            f"authn={r.get('authn_signal')} authz={r.get('authz_signal')}",
        )
        for r in mgmt_routes
        if r.get("authn_signal") not in forbid_authn
        and r.get("authn_signal") in authn_in
        and r.get("authz_signal") in authz_in
    ]
    if evidence:
        # Missing route guards are a weak control, not a confirmed anti-pattern.
        return _verdict("weak", "medium", evidence)

    unknown = [
        _route_evidence(
            r,
            f"management surface {r.get('method')} {r.get('path')} "
            f"authn={r.get('authn_signal')} — unknown does not escalate",
        )
        for r in mgmt_routes
        if r.get("authn_signal") in {"unknown", "inherited_unknown"}
    ]
    if unknown:
        return _verdict("partial", "low", unknown)
    return _verdict("present", "low", skip_reason="management routes carry positive auth signals")


def _evaluate_authz_hyp_rule(rule: CompiledRule, inventory: dict | None) -> dict:
    """ARCH-AUTHZ-001: sensitive methods (from `inventory_pattern.sensitive_methods`)
    without an authorization signal, in an application that authenticates at all."""
    if not inventory:
        return _not_applicable(_NO_INVENTORY)
    pat = rule.inventory_pattern or {}
    methods = set(pat.get("sensitive_methods", []) or [])
    authz_states = set(pat.get("require_authz_signal_in", ["absent", "unknown"]))
    min_n = int(pat.get("min_routes", 1) or 1)
    if not methods:
        return _not_applicable("no inventory_pattern.sensitive_methods configured")

    routes = inventory.get("routes", [])
    authenticated = {"present", "middleware_present", "decorator_present"}
    if not any(r.get("authn_signal") in authenticated for r in routes):
        return _not_applicable("no authenticated routes — precondition not met")

    matches = [
        _route_evidence(r, f"sensitive method {r.get('method')} {r.get('path')} authz={r.get('authz_signal')}")
        for r in routes
        if r.get("method") in methods and r.get("authz_signal") in authz_states
    ]
    if len(matches) < min_n:
        return _verdict("present", "low")
    return _verdict("weak", "medium", matches)


def _evaluate_inventory_flag_rule(rule: CompiledRule, inventory: dict | None) -> dict:
    """Hypothesis from a per-route advisory flag the inventory already computes
    (``missing_auth_suspect`` / ``missing_authz_suspect``).

    The flag is a *suspect*, never a proof: the inventory's window scan cannot
    see a centralised gate. A match therefore seeds an investigate-class
    hypothesis, never a hard finding."""
    if not inventory:
        return _not_applicable(_NO_INVENTORY)
    pat = rule.inventory_pattern or {}
    flag = pat.get("route_flag")
    min_n = int(pat.get("min_routes", 1) or 1)
    if not flag:
        return _not_applicable("no inventory_pattern.route_flag configured")
    matches = [
        _route_evidence(
            r, f"{r.get('method')} {r.get('path')} authn={r.get('authn_signal')} authz={r.get('authz_signal')}"
        )
        for r in inventory.get("routes", []) or []
        if r.get(flag) is True
    ]
    if len(matches) < min_n:
        return _verdict("present", "low")
    return _verdict("weak", "medium", matches[:_MAX_EVIDENCE_ITEMS])


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
#
# Most rules are evaluated generically from their YAML patterns
# (`_evaluate_hard_rule`, `_evaluate_hypothesis_rule`). These rule IDs have a
# dedicated evaluator because their evidence is not a single matching line:
#   ARCH-MGMT-001   route inventory: management routes without authn/authz
#   ARCH-XSS-002    stored XSS: a persistence line and a matching sink line
#   ARCH-AUTHZ-001  route inventory: sensitive methods without authz
#   ARCH-DBSEP-001  thorough-only database principal separation sidecar
# A hypothesis rule with `inventory_pattern.route_flag` reads that route flag.
# Renaming one of these IDs in the YAML silently moves it to the generic path.


def _aggregate_hits_for_rule(
    repo_root: Path,
    rule: CompiledRule,
    source_snapshot: SourceSnapshot | None = None,
) -> PatternHits:
    agg = PatternHits()
    sources = source_snapshot if source_snapshot is not None else _load_source_snapshot(repo_root)
    for rel, lines in sources:
        hits = _scan_file_for_rule(rel, lines, rule)
        agg.precondition.extend(hits.precondition)
        agg.positive.extend(hits.positive)
        agg.cooccurrence.extend(hits.cooccurrence)
        agg.exculpatory.extend(hits.exculpatory)
    return agg


def _verdict_without_positive(hits: PatternHits, skip_reason: str) -> dict:
    """Preconditions held but no unsafe line qualified: a safe form proves the
    control present, otherwise the evidence is inconclusive (partial)."""
    if hits.exculpatory:
        return _verdict("present", "medium", _evidence_dicts(hits.exculpatory[:2]))
    return _verdict("partial", "low", skip_reason=skip_reason)


def _evaluate_hard_rule(
    rule: CompiledRule,
    repo_root: Path,
    inventory: dict | None,
    source_snapshot: SourceSnapshot | None = None,
) -> dict:
    """Generic hard rule: precondition, then positive hits (optionally near a
    co-occurrence hit). Any exculpatory hit in the repository caps the result
    at weak / medium confidence."""
    if rule.rule_id == "ARCH-MGMT-001":
        return _evaluate_mgmt_rule(rule, inventory)

    hits = _aggregate_hits_for_rule(repo_root, rule, source_snapshot)
    if rule.precondition_patterns and not hits.precondition:
        return _not_applicable("no precondition signal in repo")

    if rule.cooccurrence_window > 0 or rule.cooccurrence_patterns:
        effective_positive = _cooccurrence_satisfied(hits, rule.cooccurrence_window)
    else:
        effective_positive = hits.positive
    if not effective_positive:
        return _verdict_without_positive(hits, "preconditions present but no positive/exculpatory signal")

    status = "anti_pattern" if rule.output == "anti_pattern_candidate" else "weak"
    if hits.exculpatory:
        return _verdict("weak", "medium", _evidence_dicts(effective_positive))
    return _verdict(status, "high", _evidence_dicts(effective_positive))


def _evaluate_db_principal_separation_rule(assessment_depth: str, db_separation: dict | None) -> dict:
    """Translate the thorough-only DB separation sidecar into one rule verdict.

    The sidecar is not consulted below thorough depth, including when a stale
    sidecar exists from a prior run. Confirmed records are deliberately the
    only path to proof_state=confirmed; opaque secret/config references remain
    evidence-backed review hypotheses.
    """
    if assessment_depth != "thorough":
        return _not_applicable("database principal separation is assessed only at thorough depth")
    if not db_separation or db_separation.get("skipped"):
        return _not_applicable("database principal separation sidecar is unavailable")

    def combined_evidence(records: list[dict]) -> list[dict]:
        """Keep this architecture rule to one finding, not one per principal.

        The sidecar retains separate technical records for auditability. The
        report-facing rule deliberately joins their distinct evidence locations
        into one capped, de-duplicated evidence set so a repository with many
        similarly misconfigured pools is actionable rather than noisy.
        """
        evidence: list[dict] = []
        seen: set[tuple[str, int, str]] = set()
        for record in records:
            for item in record.get("evidence") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    key = (str(item.get("file") or ""), int(item.get("line")), str(item.get("signal") or ""))
                except (TypeError, ValueError):
                    continue
                if not key[0] or key in seen:
                    continue
                seen.add(key)
                evidence.append({"file": key[0], "line": key[1], "signal": key[2]})
                if len(evidence) == _MAX_EVIDENCE_ITEMS:
                    return evidence
        return evidence

    confirmed = db_separation.get("confirmed_findings") or []
    if confirmed:
        return _verdict("weak", "high", combined_evidence(confirmed), proof_state="confirmed")
    hypotheses = db_separation.get("hypotheses") or []
    if hypotheses:
        return _verdict("weak", "medium", combined_evidence(hypotheses), proof_state="evidence-backed")
    return _verdict("present", "medium")


def _evaluate_hypothesis_rule(
    rule: CompiledRule,
    repo_root: Path,
    inventory: dict | None,
    *,
    assessment_depth: str = "standard",
    db_separation: dict | None = None,
    source_snapshot: SourceSnapshot | None = None,
) -> dict:
    """Generic hypothesis rule: positive hits make the control weak; an
    exculpatory hit anywhere lowers that to partial / low confidence."""
    if rule.rule_id == "ARCH-DBSEP-001":
        return _evaluate_db_principal_separation_rule(assessment_depth, db_separation)
    if rule.rule_id == "ARCH-AUTHZ-001":
        return _evaluate_authz_hyp_rule(rule, inventory)
    if (rule.inventory_pattern or {}).get("route_flag"):
        return _evaluate_inventory_flag_rule(rule, inventory)

    hits = _aggregate_hits_for_rule(repo_root, rule, source_snapshot)
    if rule.precondition_patterns and not hits.precondition:
        return _not_applicable("no precondition signal in repo")
    if not hits.positive:
        return _verdict_without_positive(hits, "preconditions present but no positive signal")
    if hits.exculpatory:
        return _verdict("partial", "low", _evidence_dicts(hits.positive))
    return _verdict("weak", "medium", _evidence_dicts(hits.positive))


def _evaluate_stored_xss_rule(
    rule: CompiledRule,
    repo_root: Path,
    source_snapshot: SourceSnapshot | None = None,
) -> dict:
    """Confirm a narrow, statically traceable stored-XSS path.

    This is intentionally not a general taint engine. It accepts only a direct
    object-field mapping such as ``body: req.body.content`` on the same line as
    ``Comment.create(...)`` and a later unsafe sink that reads ``comment.body``.
    Variable indirection, API contracts, serializers, and sanitizer wrappers
    require the normal STRIDE/abuse-case verification rather than a guessed
    deterministic finding.
    """
    persisted: dict[tuple[str, str], tuple[str, int, str]] = {}
    source_lines: list[tuple[str, int, str]] = []

    # Pass 1: every direct request-field-to-persistence mapping, keyed by
    # (model, field). Pass 2 below then looks for sinks, so the result does not
    # depend on which file the walk reaches first.
    sources = source_snapshot if source_snapshot is not None else _load_source_snapshot(repo_root)
    for rel, lines in sources:
        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue
            source_lines.append((rel, line_no, line))
            model_match = _PERSISTENCE_MODEL_CALL.search(line)
            if not model_match:
                continue
            for match in _REQUEST_FIELD_ASSIGNMENT.finditer(line):
                field = match.group("property") or match.group("input")
                key = (model_match.group("model").casefold(), field.casefold())
                if key not in persisted:
                    persisted[key] = (
                        rel,
                        line_no,
                        "request field "
                        f"`{match.group('input')}` is persisted as `{field}` on "
                        f"`{model_match.group('model')}`: {line}",
                    )

    # Pass 2: an unsanitized HTML sink that renders `<model>.<field>` for one of
    # the persisted pairs.
    sinks: dict[tuple[str, str], tuple[str, int, str]] = {}
    for rel, line_no, line in source_lines:
        if not _UNSAFE_HTML_SINK.search(line) or _SINK_SANITIZER.search(line):
            continue
        for model, field in persisted:
            field_ref = re.compile(rf"(?i)\b(?P<object>[A-Za-z_][A-Za-z0-9_]*)\.[ \t]*{re.escape(field)}\b")
            field_match = field_ref.search(line)
            if field_match and field_match.group("object").casefold() == model and (model, field) not in sinks:
                sinks[(model, field)] = (
                    rel,
                    line_no,
                    f"unsafe HTML sink renders `{model}.{field}`: {line}",
                )

    matched_fields = sorted(set(persisted) & set(sinks))
    if not matched_fields:
        return _not_applicable("no direct request-field persistence to matching unsafe HTML sink")

    model, field = matched_fields[0]
    return _verdict("anti_pattern", "high", _evidence_dicts([persisted[(model, field)], sinks[(model, field)]]))


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
        return (
            "emit_control_and_threat_candidate"
            if rule.output == "anti_pattern_candidate"
            else "emit_anti_pattern_candidate"
        )
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


def _rule_record(rule: CompiledRule, verdict: dict, decision: str) -> dict:
    """One `rules_evaluated[]` entry; every rule gets one, matched or not."""
    return _with_arch_fields(
        {
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
        },
        rule,
    )


def _control_assessment(rule: CompiledRule, status: str, verdict: dict, hypothesis_ids: list[str]) -> dict:
    return _with_arch_fields(
        {
            "rule_id": rule.rule_id,
            "control": rule.control,
            "domain": rule.domain,
            "status": status,
            "confidence": verdict["confidence"],
            "evidence": verdict["evidence"],
            "hypothesis_ids": hypothesis_ids,
        },
        rule,
    )


def _anti_pattern_candidate(rule: CompiledRule, verdict: dict) -> dict:
    # stride and threat_category_id come from the rule YAML: the schema requires
    # stride on every anti-pattern, and the bridge's rule-id fallback map
    # (_DOMAIN_TO_STRIDE) does not cover every rule.
    return _with_arch_fields(
        {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "cwe": rule.cwe,
            "domain": rule.domain,
            "stride": rule.stride,
            "threat_category_id": rule.threat_category_id,
            "severity_cap": rule.severity_cap,
            "evidence": verdict["evidence"],
            "confidence": verdict["confidence"],
            "must_not_carry_cvss": True,
        },
        rule,
    )


def _threat_hypothesis(rule: CompiledRule, verdict: dict, hyp_id: str) -> dict:
    return _with_arch_fields(
        {
            "hypothesis_id": hyp_id,
            "rule_id": rule.rule_id,
            "title": rule.title,
            "threat_category_id": rule.threat_category_id,
            "stride": rule.stride,
            "cwe": rule.cwe,
            "component_id": None,
            "domain": rule.domain,
            "surface": None,
            "proof_state": verdict.get("proof_state", "control-derived"),
            "confidence": verdict["confidence"],
            "weak_or_missing_controls": rule.weak_or_missing_controls,
            "positive_signals": verdict["evidence"],
            "negative_signals": [],
            "exculpatory_signals": [],
            "decision": "emit_hypothesis_only",
        },
        rule,
    )


def run(
    repo_root: Path,
    output_dir: Path | None,
    rules_data: dict,
    *,
    assessment_depth: str = "standard",
) -> dict:
    """Evaluate the hard and hypothesis rules against the repository and return the coverage document.

    A hard rule becomes an anti-pattern candidate only for an ``anti_pattern_candidate`` rule with high-confidence
    evidence. Every applicable hypothesis rule whose control is not present emits a hypothesis. Database privilege
    separation is read only at ``thorough`` depth.
    """
    inventory: dict | None = None
    if output_dir is not None:
        inventory = _load_json_or_none(output_dir / ".route-inventory.json")
    db_separation = (
        _load_json_or_none(output_dir / ".db-privilege-separation.json")
        if output_dir is not None and assessment_depth == "thorough"
        else None
    )
    source_snapshot = _load_source_snapshot(repo_root)

    rules_evaluated: list[dict] = []
    control_assessments: list[dict] = []
    anti_patterns: list[dict] = []
    hypotheses: list[dict] = []

    for rule_dict in rules_data.get("hard_rules", []) or []:
        rule = _compile_rule(rule_dict)
        if rule.rule_id == "ARCH-XSS-002":
            verdict = _evaluate_stored_xss_rule(rule, repo_root, source_snapshot)
        else:
            verdict = _evaluate_hard_rule(rule, repo_root, inventory, source_snapshot)
        rules_evaluated.append(_rule_record(rule, verdict, _decision_for_hard(rule, verdict)))

        if verdict["applies"] and verdict["status"] in {"partial", "weak", "missing", "anti_pattern"}:
            control_assessments.append(_control_assessment(rule, verdict["status"], verdict, []))
        if (
            rule.output == "anti_pattern_candidate"
            and verdict["status"] == "anti_pattern"
            and verdict["confidence"] == "high"
            and verdict["evidence"]
        ):
            anti_patterns.append(_anti_pattern_candidate(rule, verdict))

    # Hypothesis IDs are numbered per prefix in rule order: <prefix>-001, -002, ...
    hyp_counter: dict[str, int] = {}
    for rule_dict in rules_data.get("hypothesis_rules", []) or []:
        rule = _compile_rule(rule_dict)
        verdict = _evaluate_hypothesis_rule(
            rule,
            repo_root,
            inventory,
            assessment_depth=assessment_depth,
            db_separation=db_separation,
            source_snapshot=source_snapshot,
        )
        rules_evaluated.append(_rule_record(rule, verdict, _decision_for_hypothesis(rule, verdict)))

        if not verdict["applies"] or verdict["status"] in {"present", "not_applicable"}:
            continue
        prefix = rule.hypothesis_id_prefix or "ARCH-HYP-GEN"
        hyp_counter[prefix] = hyp_counter.get(prefix, 0) + 1
        hyp_id = f"{prefix}-{hyp_counter[prefix]:03d}"
        hypotheses.append(_threat_hypothesis(rule, verdict, hyp_id))
        if rule.output == "control_and_hypothesis":
            control_assessments.append(_control_assessment(rule, "partial", verdict, [hyp_id]))

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(repo_root),
        "rules_evaluated": rules_evaluated,
        "control_assessments": control_assessments,
        "threat_hypotheses": hypotheses,
        "anti_pattern_candidates": anti_patterns,
        # Required by the schema; no evaluator reports warnings yet.
        "warnings": [],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="architecture_coverage_checks.py", description=__doc__)
    p.add_argument("--repo-root", required=True)
    p.add_argument("--output-dir", help="If provided, writes .architecture-coverage.json there.")
    p.add_argument("--rules-yaml", help="Override path to architecture-coverage-rules.yaml.")
    p.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"), default="standard")
    p.add_argument("--stdout", action="store_true")
    args = p.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"analyzers/architecture_coverage_checks.py: repo-root not found: {repo_root}", file=sys.stderr)
        return 1
    output_dir = Path(args.output_dir) if args.output_dir else None

    rules = _load_rules(Path(args.rules_yaml) if args.rules_yaml else None)
    result = run(repo_root, output_dir, rules, assessment_depth=args.assessment_depth)

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
