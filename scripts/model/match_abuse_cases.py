#!/usr/bin/env python3
"""model/match_abuse_cases.py — deterministic abuse-case matcher + verdict finalizer.

No LLM. Runs in Phase 10b before the abuse-case verifier agents are dispatched.

Subcommands
-----------
  match            Match each active abuse case against the merged findings.
                   Writes <output-dir>/.abuse-case-matches.json.
  list-candidates  Print the ids of cases whose structural verdict is
                   `candidate` or `partial_candidate` (one per line) — the set
                   the verifier dispatcher should spawn an agent for.
  finalize         Fold per-step verifier verdicts into a chain verdict per
                   case. Reads .abuse-case-matches.json + .abuse-case-verdicts.json,
                   writes .abuse-case-verdicts.json (enriched, in place).

Matching algorithm (per case)
-----------------------------
  * scope_qualifier — when a recon signals set is supplied, every
    `required_signals` entry must be present, else the case is `not_applicable`.
    When no signals file is given, scope is treated as satisfied (the matcher
    never produces a false negative from a missing signals source). Auth, role,
    and client-storage signals from the canonical recon sidecar must be backed
    by a runtime source location rather than documentation or scanner metadata.
  * per step — `probe.sink_patterns` (regex) are matched against each finding's
    searchable text (title + scenario + cwe + component + evidence excerpt).
    The best-scoring finding is the step's `matched_finding_id`: each matching
    pattern contributes a specificity weight (CWE-code alternation > code-
    structural regex > bare prose phrase), a CWE bonus counts only against the
    finding's own `cwe` field, and context-dependent CWEs need a matching
    domain-specific sink as corroboration. Steps de-duplicate across a chain so
    a two-step chain does not collapse onto one finding.
    `probe.control_patterns` matched against the finding's controls text mark a
    step as control-guarded.
  * structural verdict:
      all required steps matched  -> candidate
      no required step matched     -> not_applicable
      some required steps matched  -> partial_candidate
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import fnmatch
import importlib.util
import json
import re
import sys
from functools import lru_cache
from pathlib import Path

import analyzers.scan_excludes as scan_excludes
import yaml
from shared._finding_state import is_refuted
from shared._severity_policy import abuse_case_priority, normalize_risks
from validators.validate_intermediate import validate_recon_signals

PLUGIN_ROOT = Path(__file__).resolve().parents[2]


def _rac():
    spec = importlib.util.spec_from_file_location(
        "resolve_abuse_cases", Path(__file__).resolve().parents[1] / "model/resolve_abuse_cases.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Finding loading + searchable-text projection
# ---------------------------------------------------------------------------


def _finding_id(finding: dict) -> str:
    return (finding.get("f_id") or finding.get("t_id") or finding.get("id") or "").strip()


def _finding_text(finding: dict) -> str:
    """Concatenate the fields a sink/control pattern can legitimately match."""
    parts = [
        finding.get("title", ""),
        finding.get("scenario", ""),
        finding.get("cwe", ""),
        finding.get("component", ""),
        finding.get("component_id", ""),
    ]
    ev = finding.get("evidence") or {}
    if isinstance(ev, dict):
        parts += [str(ev.get("file", "")), str(ev.get("excerpt", "")), str(ev.get("snippet", ""))]
    return "\n".join(p for p in parts if p)


def _controls_text(finding: dict) -> str:
    """Text to probe for PRESENT controls.

    ``controls_absent_evidence`` documents the controls a finding proves are
    MISSING, so folding it in here inverted the probe: a finding whose absent-
    evidence read "no ownership check on this path" matched the ``ownership``
    control pattern and was recorded as a control *found* (2026-07-25
    insecure-spring-app AC-T-002 step 1 → chain wrongly finalized
    partially_blocked). Only `controls_in_place` may feed a controls-present
    probe.

    This probe stays a coarse substring heuristic either way — `controls_in_place`
    prose can still name a control while negating it ("None on the detail page —
    edit and delete use loadAllowedOrder() which does enforce ownership"). That
    residual imprecision is contained downstream: ``finalize_verdict`` treats this
    value as a hint only and lets the verifier's empirical observation override it.
    """
    return finding.get("controls_in_place", "") or ""


def load_findings(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        return doc.get("findings") or doc.get("threats") or []
    return doc if isinstance(doc, list) else []


def matchable_findings(findings: list[dict]) -> list[dict]:
    """Exclude findings that authoritative evidence verification refuted."""
    return [finding for finding in findings if not is_refuted(finding)]


def _compile(patterns: list[str]) -> list[re.Pattern]:
    out = []
    for p in patterns or []:
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error:
            # Treat an invalid regex as a literal substring match.
            out.append(re.compile(re.escape(p), re.IGNORECASE))
    return out


# ---------------------------------------------------------------------------
# Step + case matching
# ---------------------------------------------------------------------------


def _pattern_specificity(pat: str) -> int:
    """Rank a sink pattern by how discriminating it is.

    A CWE-code alternation is the strongest, most specific signal (weight 5); a
    code-structural regex that matches source syntax (backslash escapes like
    ``\\.``, ``\\(``, ``\\s``) is moderately specific (weight 2); a bare ``(?i)``
    prose phrase is weak (weight 1) because it also matches an incidental mention
    in an unrelated finding's scenario. This is what stops a mass-assignment step
    (``CWE-915``) from being captured by an IDOR finding that merely says
    "escalate own role" in its prose (juice-shop 2026-07-13: AC-T-002/003/004 all
    mis-linked mass-assignment / role-claim steps to F-008 IDOR).
    """
    if "CWE-" in pat.upper():
        return 5
    if "\\" in pat:  # code-structural regex — matches source syntax, not prose
        return 2
    return 1


_CWE_ID_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _is_code_sink_pattern(pat: str) -> bool:
    """Whether a sink pattern targets source code rather than prose or a CWE.

    Catalog sink patterns come in three flavours: a ``CWE-(...)`` alternation,
    a case-insensitive ``(?i)`` English phrase, and a case-sensitive code
    token or shape (``innerHTML``, ``req\\.user\\.role``). Only the last kind
    can meaningfully be searched for in application source."""
    if "CWE-" in pat.upper():
        return False
    return "(?i)" not in pat


def _cwe_code(value: object) -> str:
    """Bare numeric CWE code from a ``CWE-639`` style field, else ``""``."""
    if not isinstance(value, str):
        return ""
    hit = _CWE_ID_RE.search(value)
    return hit.group(1) if hit else ""


# These CWEs describe a weakness class that commonly spans unrelated domains.
# A finding with only one of them is useful triage input, but is not sufficient
# evidence that a particular abuse-case mechanism exists. For example, CWE-347
# can describe unsigned artifact provenance as well as JWT verification. The
# CWE-74 parent spans injection into many downstream components and does not by
# itself establish a server-side interpreter or code-execution sink. The
# matcher therefore requires an accompanying code or mechanism phrase from the
# case probe before dispatching an expensive verifier for these CWEs.
_CONTEXT_DEPENDENT_CWES = frozenset({"74", "284", "287", "347", "384"})

_RUNTIME_SURFACE_SIGNALS = frozenset({"has_auth_surface", "has_role_concept", "has_client_storage"})
_NON_RUNTIME_EVIDENCE_PREFIXES = (
    "agents/",
    "data/",
    "docs/",
    "examples/",
    "tests/",
    ".github/",
)

# A source probe is deliberately a *candidate generator*, not a verdict.  It
# closes the historic blind spot where a configured scenario was never
# investigated merely because upstream analysis did not emit a matching
# finding.  The verifier still has to establish reachability and controls.
_SOURCE_PROBE_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target"})
_SOURCE_PROBE_MAX_FILES = 5_000
_SOURCE_PROBE_MAX_BYTES = 1_000_000


def _safe_repo_glob(pattern: object) -> str | None:
    """Return a repository-relative glob, or ``None`` for an unsafe value."""
    if not isinstance(pattern, str) or not pattern.strip():
        return None
    normalized = pattern.replace("\\", "/")
    if normalized.startswith("/") or any(part == ".." for part in normalized.split("/")):
        return None
    return normalized


@lru_cache(maxsize=8)
def _repo_source_files(repo_root: Path) -> tuple[Path, ...]:
    """Return a bounded, deterministic inventory for direct source probes."""
    files: list[Path] = []
    try:
        for path in sorted(repo_root.rglob("*")):
            try:
                rel = path.relative_to(repo_root)
            except ValueError:
                continue
            if any(part in _SOURCE_PROBE_SKIP_DIRS for part in rel.parts):
                continue
            relative = rel.as_posix()
            try:
                if scan_excludes.is_excluded(relative):
                    continue
            except (FileNotFoundError, ValueError):
                # Keep the matcher usable in a partially packaged plugin, but
                # retain the local hard exclusions above as the fail-open floor.
                pass
            if not path.is_file():
                continue
            try:
                if path.stat().st_size > _SOURCE_PROBE_MAX_BYTES:
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= _SOURCE_PROBE_MAX_FILES:
                break
    except OSError:
        return tuple(files)
    return tuple(files)


def _glob_matches(relative_path: Path, patterns: list[str]) -> bool:
    """Match a repo-relative path without ever interpreting user data as a path."""
    for pattern in patterns:
        if relative_path.match(pattern):
            return True
        # pathlib's ``match`` treats ``**/`` as one-or-more path components,
        # while users conventionally expect ``services/**/*.py`` to include
        # ``services/payments.py`` as well.  Test the zero-directory variant
        # explicitly without handing the pattern to a shell or filesystem glob.
        if "/**/" in pattern and relative_path.match(pattern.replace("/**/", "/")):
            return True
    return False


def _source_probe(step: dict, repo_root: Path | None) -> dict | None:
    """Return direct source evidence for a step's sink, if present.

    A hit only means "this scenario deserves verification".  It intentionally
    does not claim the sink is reachable or vulnerable; that remains the
    verifier's code-reading job.
    """
    if repo_root is None or not repo_root.is_dir():
        return None
    probe = step.get("probe") or {}
    # Probe source with the CODE patterns only. A CWE code never appears in
    # application source, and a case-insensitive prose phrase matches any file
    # that merely discusses the topic — juice-shop 2026-07-24 returned an
    # Arabic i18n string for "privilege escalation" as evidence of a role-claim
    # sink. Catalog prose patterns are authored `(?i)` precisely because they
    # target English text; code patterns are case-sensitive. Keeping only the
    # latter makes this a sink probe again rather than a full-text search.
    sinks = _compile([p for p in (probe.get("sink_patterns") or []) if _is_code_sink_pattern(p)])
    if not sinks:
        return None
    hints = [p for p in (_safe_repo_glob(v) for v in (probe.get("entry_points") or {}).get("file_hints", [])) if p]
    for path in _repo_source_files(repo_root):
        rel = path.relative_to(repo_root)
        rel_str = str(rel).replace("\\", "/")
        # Apply the same evidence policy the rest of the matcher uses. Without
        # it the probe walked the assessment's OWN output directory and
        # returned a line out of `docs/security/.abuse-case-matches.json` as
        # "source evidence" for a role-claim step (juice-shop 2026-07-24) —
        # the scan quoting its own prior output back at itself.
        if not _is_runtime_surface_evidence(rel_str):
            continue
        if hints and not _glob_matches(rel, hints):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if any(rx.search(line) for rx in sinks):
                return {"file": str(rel).replace("\\", "/"), "line": line_no, "excerpt": line.strip()[:300]}
    return None


def _is_context_dependent_cwe_match(cwe_field: str, raw_pattern: str, rx: re.Pattern) -> bool:
    """Return whether a matching CWE pattern is too broad to stand alone."""
    if "CWE-" not in raw_pattern.upper() or not rx.search(cwe_field):
        return False
    return bool(set(_CWE_ID_RE.findall(cwe_field)) & _CONTEXT_DEPENDENT_CWES)


def _is_runtime_surface_evidence(evidence: object) -> bool:
    """Reject catalog, documentation, test, and CI evidence for app surfaces."""
    if isinstance(evidence, str):
        normalized = evidence.strip().lower()
        return bool(normalized) and not normalized.startswith(_NON_RUNTIME_EVIDENCE_PREFIXES)
    if not isinstance(evidence, dict) or evidence.get("status") != "supporting":
        return False
    locations = evidence.get("locations")
    if not isinstance(locations, list):
        return False
    return any(
        isinstance(location, dict)
        and isinstance(location.get("file"), str)
        and not location["file"].strip().lower().startswith(_NON_RUNTIME_EVIDENCE_PREFIXES)
        for location in locations
    )


def match_step(
    step: dict,
    findings: list[dict],
    exclude_ids: set[str] | None = None,
    repo_root: Path | None = None,
    prefer_files: frozenset[str] = frozenset(),
) -> dict:
    """Match one chain step to its best-fitting finding.

    Scoring (not first-match): every sink pattern that hits a finding contributes
    its ``_pattern_specificity`` weight, but a CWE pattern earns its strong bonus
    only when it matches the finding's OWN ``cwe`` field (not an incidental CWE
    mention in prose). The highest-scoring finding wins. Equal scores prefer a
    finding whose evidence file another step of the same chain matched
    (``prefer_files``): a chain runs through shared code, while the step's own
    CWE only names a class. Then the declared CWE, a finding not already consumed
    by an earlier step (``exclude_ids``) so a two-step chain does not degenerate
    into the same finding twice, and finally finding list order (deterministic).
    """
    exclude_ids = exclude_ids or set()
    probe = step.get("probe") or {}
    raw_sinks = probe.get("sink_patterns") or []
    sinks = _compile(raw_sinks)
    controls = _compile(probe.get("control_patterns") or [])
    # The catalog declares the CWE this chain step is ABOUT. A finding carrying
    # exactly that CWE is the intended target; one that merely falls inside the
    # step's CWE-family alternation is not.
    step_cwe = _cwe_code((step.get("finding") or {}).get("cwe"))

    matched_id = None
    matched_evidence = None
    controls_found: list[str] = []
    best_key: tuple | None = None
    best_is_weak = False
    top_score = 0
    weak_tie_ids: set[str] = set()
    for idx, finding in enumerate(findings):
        # The source probe's evidence policy applies to bound findings too. A
        # CI-workflow finding classified CWE-269 bound to a registration step
        # by its CWE family (juice-shop 2026-10-08), and the chain then raised
        # that workflow finding to Critical as its keystone.
        ev = finding.get("evidence")
        ev_file = ev.get("file") if isinstance(ev, dict) else None
        if isinstance(ev_file, str) and not _is_runtime_surface_evidence(ev_file):
            continue
        text = _finding_text(finding)
        cwe_field = (finding.get("cwe") or "").strip()
        score = 0
        has_mechanism_match = False
        has_context_dependent_cwe_match = False
        has_family_cwe_match = False
        has_code_match = False
        # Distinct from has_mechanism_match, which is also set for a plain
        # CWE-field hit: this is true only when a NON-CWE pattern matched, i.e.
        # the step's actual code shape or phrasing was found in the finding.
        has_non_cwe_match = False
        for raw, rx in zip(raw_sinks, sinks):
            if not rx.search(text):
                continue
            spec = _pattern_specificity(raw)
            if spec != 5:
                has_non_cwe_match = True
            if spec == 2:
                has_code_match = True
            # A CWE pattern only earns its strong bonus when it matches the
            # finding's OWN cwe field, not a CWE named in passing in the prose.
            if spec == 5 and not (cwe_field and rx.search(cwe_field)):
                spec = 1
            elif spec == 5 and _is_context_dependent_cwe_match(cwe_field, raw, rx):
                has_context_dependent_cwe_match = True
            else:
                has_mechanism_match = True
                if spec == 5:
                    has_family_cwe_match = True
            score += spec
        if has_context_dependent_cwe_match and not has_mechanism_match:
            continue
        if score <= 0:
            continue
        fid = _finding_id(finding)
        exact_cwe = bool(step_cwe) and _cwe_code(cwe_field) == step_cwe
        # A generic phrase such as "privilege escalation" can occur in an
        # unrelated IDOR, authentication, or sandbox finding. When the case
        # declares a CWE, a differently classified finding must also match the
        # case's CWE family or a code-structural sink. Prose alone is not a
        # stable binding and otherwise sends an expensive verifier to the wrong
        # source location.
        if step_cwe and not exact_cwe and not has_family_cwe_match and not has_code_match:
            continue
        # A match resting ONLY on a multi-CWE family alternation — no mechanism
        # pattern, and not the step's own declared CWE — is not evidence that
        # THIS finding implements THIS step. Several unrelated findings share a
        # family, so the pre-2026-07-24 tie-break (finding list order) picked
        # one arbitrarily: juice-shop AC-T-003 step 2 ("role claim trusted from
        # token") bound to a chatbot discount-coupon finding because both are
        # CWE-862, and the verifier then burned its whole turn budget
        # discovering the binding was nonsense.
        weak = not has_non_cwe_match and not exact_cwe
        coherent = bool(ev_file) and ev_file in prefer_files
        # A lone weak match is no better evidence than a tied one when the step
        # declares its own CWE: with the CI finding filtered, AC-T-003 step 2
        # bound the coupon finding again (juice-shop 2026-10-08). It stays
        # eligible only where the chain runs through its file.
        if weak and step_cwe and not coherent:
            continue
        if score > top_score:
            top_score = score
            weak_tie_ids = {fid} if weak else set()
        elif score == top_score and weak:
            weak_tie_ids.add(fid)
        # Maximise: score, chain coherence, the step's own CWE, real mechanism
        # evidence, then prefer a not-yet-consumed finding, then earliest.
        key = (score, coherent, exact_cwe, has_non_cwe_match, fid not in exclude_ids, -idx)
        if best_key is None or key > best_key:
            best_key = key
            best_is_weak = weak
            matched_id = fid
            ev = finding.get("evidence") or {}
            matched_evidence = {
                "file": ev.get("file") if isinstance(ev, dict) else None,
                "line": ev.get("line") if isinstance(ev, dict) else None,
            }
            ctext = _controls_text(finding)
            controls_found = [rx.pattern for rx in controls if rx.search(ctext)]

    # Ambiguous family-only tie: drop the binding entirely rather than guess.
    # The step then falls through to the source probe below, which greps the
    # repository for the step's own mechanism patterns — strictly better
    # evidence than an arbitrarily chosen same-family finding.
    if matched_id is not None and best_is_weak and len(weak_tie_ids) > 1:
        matched_id = None
        matched_evidence = None
        controls_found = []

    direct_evidence = None
    if matched_id is None:
        direct_evidence = _source_probe(step, repo_root)

    return {
        "step": step.get("step"),
        "label": step.get("label"),
        "required": step.get("required", True),
        "grants": step.get("grants"),
        "requires": step.get("requires"),
        "matched": matched_id is not None or direct_evidence is not None,
        "matched_finding_id": matched_id,
        "evidence": matched_evidence or direct_evidence,
        "match_basis": "finding" if matched_id is not None else ("source_probe" if direct_evidence else None),
        "controls_found": controls_found,
    }


def _scope_status(case: dict, signals: set[str] | None, repo_root: Path | None) -> tuple[bool, list[str], list[str]]:
    """Evaluate declarative scope gates: all signals, any path pattern."""
    qualifier = case.get("scope_qualifier") or {}
    required = qualifier.get("required_signals") or []
    unmet_signals = [] if signals is None else [sig for sig in required if sig not in signals]
    raw_patterns = qualifier.get("path_patterns") or []
    patterns = [p for p in (_safe_repo_glob(v) for v in raw_patterns) if p]
    unmet_paths: list[str] = []
    if raw_patterns:
        if repo_root is None or not repo_root.is_dir():
            # Keep compatibility with callers that do not supply a repository:
            # absence of the inventory cannot disprove applicability.
            pass
        elif not patterns or not any(
            _glob_matches(p.relative_to(repo_root), patterns) for p in _repo_source_files(repo_root)
        ):
            unmet_paths = [str(p) for p in raw_patterns]
    return not unmet_signals and not unmet_paths, unmet_signals, unmet_paths


def _match_chain(
    case: dict,
    findings: list[dict],
    repo_root: Path | None,
    *,
    prefer: dict | None = None,
    previous: list[dict] | None = None,
) -> list[dict]:
    # Thread consumed finding ids so a later step prefers a distinct finding —
    # a two-step chain (IDOR → mass-assignment) must not collapse to one finding.
    kept = {m["step"]: m for m in previous or [] if not m.get("matched_finding_id")}
    step_matches = []
    consumed: set[str] = set()
    for s in case.get("chain") or []:
        if s.get("step") in kept:
            m = kept[s.get("step")]
        else:
            m = match_step(
                s,
                findings,
                exclude_ids=consumed,
                repo_root=repo_root,
                prefer_files=(prefer or {}).get(s.get("step"), frozenset()),
            )
        if m.get("matched") and m.get("matched_finding_id"):
            consumed.add(m["matched_finding_id"])
        step_matches.append(m)
    return step_matches


def is_descriptive(case: dict) -> bool:
    """A plain-language business case without probes (schema_version 2)."""
    return isinstance(case, dict) and case.get("kind") == "descriptive"


def _finding_file(finding: dict) -> str | None:
    ev = finding.get("evidence")
    file = ev.get("file") if isinstance(ev, dict) else None
    return file.replace("\\", "/") if isinstance(file, str) and file else None


# Files a descriptive case can bind a step to: code that executes or renders
# server-side. Styles, markup, data, and backups only steer the verifier away.
_DESCRIPTIVE_SOURCE_SUFFIXES = frozenset(
    ".ts .tsx .js .jsx .mjs .cjs .py .rb .go .java .kt .kts .scala .groovy .cs .vb .fs .rs .php "
    ".c .cc .cpp .h .hpp .m .mm .swift .dart .ex .exs .erl .lua .pl .pm .vue .svelte "
    ".jsp .aspx .cshtml .erb".split()
)


# Most specific first: a route handler file can be the router that registers every route.
_LOCATORS = ("detector_rules", "path_patterns", "route_patterns")


def _descriptive_preselection(
    case: dict, findings: list[dict], repo_root: Path | None, max_files: int, routes: list[dict] | None
) -> tuple[list[str], list[str]]:
    """Return (preselected source files, related findings).

    Three locators select files, in this order: files of findings a
    detector raised under one of the ``detector_rules``, the case's
    ``path_patterns``, and handlers of routes in the route inventory whose
    path matches a ``route_patterns`` entry. A file must be executable runtime source in the
    bounded repository inventory; documentation, tests, styles, and catalog
    data are never admitted, and a route or finding cannot name a file outside
    the inventory.
    Related findings are existing, unrefuted findings located in those files:
    detector results the verifier cites as evidence instead of re-deciding.
    """
    qualifier = case.get("scope_qualifier") or {}
    if repo_root is None or not repo_root.is_dir():
        return [], []
    runtime: dict[str, Path] = {}
    for path in _repo_source_files(repo_root):
        rel = path.relative_to(repo_root)
        if path.suffix.lower() in _DESCRIPTIVE_SOURCE_SUFFIXES and _is_runtime_surface_evidence(rel.as_posix()):
            runtime[rel.as_posix()] = rel
    route_patterns = [str(v).lower() for v in qualifier.get("route_patterns") or [] if str(v).strip()]
    rules = {str(v) for v in qualifier.get("detector_rules") or []}
    path_patterns = [p for p in (_safe_repo_glob(v) for v in qualifier.get("path_patterns") or []) if p]
    located: dict[str, list[str]] = {
        "route_patterns": [
            str(route["handler_file"]).replace("\\", "/").removeprefix("./")
            for route in routes or []
            if any(fnmatch.fnmatchcase(str(route["path"]).lower(), pattern) for pattern in route_patterns)
        ],
        "detector_rules": [
            file
            for finding in findings
            if str(finding.get("source_check_id") or "") in rules
            for file in [_finding_file(finding)]
            if file
        ],
        "path_patterns": [
            rel_str for rel_str, rel in runtime.items() if path_patterns and _glob_matches(rel, path_patterns)
        ],
    }
    files: list[str] = []
    for locator in _LOCATORS:
        for file in located[locator]:
            if file in runtime and file not in files and len(files) < max_files:
                files.append(file)
    selected = set(files)
    related: dict[str, dict] = {}
    for finding in findings:
        fid = _finding_id(finding)
        if fid and fid not in related and _finding_file(finding) in selected:
            ev = finding.get("evidence") or {}
            line = ev.get("line") if isinstance(ev, dict) else None
            related[fid] = {
                "id": fid,
                "title": str(finding.get("title") or "")[:200],
                "cwe": str(finding.get("cwe") or "")[:40] or None,
                "file": _finding_file(finding),
                "line": line if type(line) is int and line >= 1 else None,
            }
    return files, [related[fid] for fid in sorted(related)][:max_files]


def _match_descriptive(
    case: dict,
    findings: list[dict],
    signals: set[str] | None,
    repo_root: Path | None,
    max_files: int,
    routes: list[dict] | None = None,
) -> dict:
    """Preselect a descriptive case deterministically; the verifier binds it.

    No regex matches a business boundary, so a step is never ``matched`` here.
    A case is a candidate when every required signal holds and, if it declares
    locators, at least one locates a runtime source file. Without that it
    reaches the verifier only through an explicit request.
    """
    qualifier = case.get("scope_qualifier") or {}
    unmet_signals = (
        [] if signals is None else [sig for sig in qualifier.get("required_signals") or [] if sig not in signals]
    )
    declared = [locator for locator in _LOCATORS if qualifier.get(locator)]
    files, related = (
        _descriptive_preselection(case, findings, repo_root, max_files, routes) if not unmet_signals else ([], [])
    )
    unlocated = bool(declared) and not files and not unmet_signals
    applicable = not unmet_signals and not unlocated
    unmet_paths = [str(p) for p in qualifier.get("path_patterns") or []] if unlocated else []
    reason = None
    if not applicable:
        reasons = []
        if unmet_signals:
            reasons.append("required signal(s) absent: " + ", ".join(unmet_signals))
        if unlocated and qualifier.get("route_patterns"):
            reasons.append(
                "no route matched: " + ", ".join(map(str, qualifier["route_patterns"]))
                if routes is not None
                else "route inventory unavailable"
            )
        if unlocated and qualifier.get("detector_rules"):
            reasons.append(
                "no runtime finding from detector rule(s): " + ", ".join(map(str, qualifier["detector_rules"]))
            )
        if unmet_paths:
            reasons.append("no runtime source path matched: " + ", ".join(unmet_paths))
        reason = "; ".join(reasons) or "scope preconditions not met for this codebase"
    steps = [
        {
            "step": index,
            "label": text,
            "required": True,
            "grants": None,
            "requires": None,
            "matched": False,
            "matched_finding_id": None,
            "evidence": None,
            "match_basis": "descriptive",
            "controls_found": [],
        }
        for index, text in enumerate(case.get("steps") or [], start=1)
    ]
    return {
        "abuse_case_id": case.get("id"),
        "title": case.get("title"),
        "source": "descriptive",
        "kind": "descriptive",
        "applicable": applicable,
        "structural_verdict": "candidate" if applicable else "not_applicable",
        "reason": reason,
        "unmet_signals": unmet_signals or None,
        "unmet_path_patterns": unmet_paths or None,
        "matched_finding_ids": [],
        "related_finding_ids": [f["id"] for f in related],
        "related_findings": related,
        "preselected_sources": files,
        "step_matches": steps,
        "case": case,
    }


def match_case(
    case: dict,
    findings: list[dict],
    signals: set[str] | None,
    repo_root: Path | None = None,
    max_descriptive_files: int = 12,
    routes: list[dict] | None = None,
) -> dict:
    if is_descriptive(case):
        return _match_descriptive(case, findings, signals, repo_root, max_descriptive_files, routes)
    applicable, unmet_signals, unmet_paths = _scope_status(case, signals, repo_root)
    step_matches = _match_chain(case, findings, repo_root if applicable else None)
    # Second pass: each step prefers findings in files its sibling steps
    # matched. Steps without a finding keep their first-pass result, so the
    # repository probe does not run twice.
    files = {
        m["step"]: (m.get("evidence") or {}).get("file")
        for m in step_matches
        if m.get("matched_finding_id") and (m.get("evidence") or {}).get("file")
    }
    prefer = {step: frozenset(file for other, file in files.items() if other != step) for step in files}
    if any(prefer.values()):
        step_matches = _match_chain(
            case, findings, repo_root if applicable else None, prefer=prefer, previous=step_matches
        )
    required = [m for m in step_matches if m["required"]]
    required_hit = [m for m in required if m["matched"]]

    # Capture WHY a case is not a candidate so the §9 renderer can show the
    # generic catalog with a short relevant/not-relevant reason instead of
    # silently dropping every evaluated-but-not-applicable case.
    reason: str | None = None
    if not applicable:
        verdict = "not_applicable"
        reasons = []
        if unmet_signals:
            reasons.append("required signal(s) absent: " + ", ".join(unmet_signals))
        if unmet_paths:
            reasons.append("no repository path matched: " + ", ".join(unmet_paths))
        reason = "; ".join(reasons) or "scope preconditions not met for this codebase"
    elif required and len(required_hit) == len(required):
        verdict = "candidate"
    elif not required_hit:
        verdict = "not_applicable"
        reason = "no finding matched the required chain step(s) for this scenario"
    else:
        verdict = "partial_candidate"
        reason = "only some required chain steps have a matching finding"

    return {
        "abuse_case_id": case.get("id"),
        "title": case.get("title"),
        "source": case.get("source"),
        "applicable": applicable,
        "structural_verdict": verdict,
        "reason": reason,
        "unmet_signals": unmet_signals or None,
        "unmet_path_patterns": unmet_paths or None,
        "matched_finding_ids": [m["matched_finding_id"] for m in step_matches if m.get("matched_finding_id")],
        "step_matches": step_matches,
        # The verifier needs the full chain definition (not merely the
        # matcher projection) for org- and repo-local cases.  It remains data,
        # never instructions, and is intentionally persisted with the audit
        # sidecar that explains why a case was selected.
        "case": case,
    }


# ---------------------------------------------------------------------------
# Chain-verdict finalisation (folds verifier step verdicts → chain verdict)
# ---------------------------------------------------------------------------

_CONFIRMED = "confirmed"
_BLOCKED = "blocked"
_REFUTED = "refuted"
_INCONCLUSIVE = "inconclusive"
# Neither verdict establishes the step: the verifier could not decide, or it
# decided the matched pairing does not hold. Both cap the chain the same way;
# they differ downstream — a refuted step is a settled result, not open work.
_UNESTABLISHED = {_INCONCLUSIVE, _REFUTED}


def _step_controls(step_match: dict, step_verdict: dict | None) -> list:
    """Controls observed for one step — the verifier overrides the matcher.

    The matcher's ``controls_found`` is a static substring probe over finding
    prose (``_step_match`` → ``_controls_text``); the verifier's is an empirical
    reading of the source at that step. When the verifier assessed the step it
    emits ``controls_found`` unconditionally (`[]` when it found none — see
    ``agents/appsec-abuse-case-verifier.md``), so a PRESENT key means the
    verifier has spoken and its observation is authoritative.

    OR-ing the two instead let a stale keyword guess outrank a code reading:
    2026-07-25 insecure-spring-app AC-T-002 step 1 — the verifier reported
    ``controls_found: []`` and "no ownership check; edit endpoint uses
    loadAllowedOrder() but detail endpoint does not", yet the matcher's
    ``['ownership']`` forced the chain to partially_blocked.

    The matcher hint is still used when the verifier never assessed the step
    (no verdict row, or a row that omits the key entirely) — there it is the
    only signal available.
    """
    if step_verdict is not None and "controls_found" in step_verdict:
        return step_verdict.get("controls_found") or []
    return step_match.get("controls_found") or []


def finalize_verdict(case_match: dict, step_verdicts: list[dict]) -> str:
    """Compute the chain verdict from per-step verifier verdicts.

    all required steps confirmed, nothing unresolved -> fully_viable
    >=1 required confirmed AND >=1 step has a control -> partially_blocked
    all required steps blocked                        -> mitigated
    any ASSESSED step inconclusive or refuted         -> inconclusive

    ``fully_viable`` is a positive claim of end-to-end exploitability, so it
    requires every step the verifier actually assessed to be ``confirmed`` —
    not merely the ``required`` subset. See the inconclusive cap below.

    A ``refuted`` step (the verifier established that the matched pairing does
    not hold) caps the chain exactly like an inconclusive one: the chain as
    matched is not an established path, and no chain-level verdict claims more.
    The step keeps its own verdict, so §9 and the completion summary can tell
    a settled mismatch from open work.
    """
    by_step = {v.get("step"): v for v in step_verdicts}
    step_matches = case_match.get("step_matches", [])
    required_steps = [s for s in step_matches if s.get("required", True)]
    if not required_steps:
        return "not_applicable"

    verdicts = [(by_step.get(s.get("step")) or {}).get("verdict", _INCONCLUSIVE) for s in required_steps]
    # Controls from EVERY step (required or not) — a control anywhere on the
    # chain impedes it. Per step the verifier's reading wins over the matcher's.
    any_control = any(_step_controls(s, by_step.get(s.get("step"))) for s in step_matches)

    if all(v == _BLOCKED for v in verdicts):
        return "mitigated"
    if any(v in _UNESTABLISHED for v in verdicts):
        return "inconclusive"
    # An inconclusive step ANYWHERE on the chain caps the verdict, whether the
    # matcher flagged that leg `required` or not, and whether the verifier left
    # it untouched (turn-ceiling cut-off) or examined it and recorded a reason.
    #
    # The pre-2026-07-25 rule capped only UNTOUCHED pre-seeds and deliberately
    # let a reasoned inconclusive on a non-required leg stand as fully_viable,
    # on the theory that "the attack is still viable through the required path".
    # That theory does not hold for the chain shapes this catalog actually
    # declares: every `required: false` step in data/abuse-cases is the chain's
    # PAYOFF, not an optional alternative leg —
    #   AC-T-001 step 3  "Stolen token accepted for a new session"
    #   AC-T-003 step 2  "Role claim trusted from token without re-fetch"
    #   AC-T-005 step 2  "Stolen material is accepted by the verification path"
    # They carry `required: false` because they are rarely evidenced as their own
    # finding, not because the attack succeeds without them. So the required path
    # is the SETUP and the non-required step is where the attack pays off.
    #
    # 2026-07-25 insecure-spring-app AC-T-005: step 1 confirmed (JWT_SIGNING_KEY
    # hardcoded at Dockerfile:13), step 2 inconclusive because SignedJwtService
    # generates a random in-memory key — the exposed secret is NOT the one the
    # server trusts, so the bypass does not follow. The old rule still published
    # "⚠ Fully viable · 🔴 Critical" and counted it among the viable chains,
    # while runtime/aggregate_run_issues.py concurrently flagged the same chain as "not
    # verified end-to-end". A chain whose payoff was never established must not
    # carry a positive viability claim.
    #
    # `inconclusive` loses nothing: §9 still renders the case with every step and
    # its individual verdict, `_combined_risk` simply stops applying the
    # fully-viable severity escalation, and triage_compute_ranking stops
    # elevating the member findings off an unproven chain.
    if any(v.get("verdict") in _UNESTABLISHED for v in step_verdicts):
        return "inconclusive"
    confirmed = [v == _CONFIRMED for v in verdicts]
    if all(confirmed):
        return "partially_blocked" if any_control else "fully_viable"
    # mix of confirmed + blocked, none unestablished
    if any(confirmed):
        return "partially_blocked"
    return "inconclusive"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_signals(path: str | None, repo_root: Path | None = None) -> set[str] | None:
    if not path:
        return None
    signal_path = Path(path)
    if not signal_path.is_file():
        return None
    doc = json.loads(signal_path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        # Accept a direct {signal: bool} map, {signals: [name, ...]}, and the
        # recon sidecar's canonical {signals: {name: bool}} shape.
        if isinstance(doc.get("signals"), dict):
            valid, _errors = validate_recon_signals(doc, repo_root=repo_root)
            if not valid:
                return None
            active = {str(k) for k, v in doc["signals"].items() if v}
            evidence = doc.get("signal_evidence")
            if isinstance(evidence, dict):
                active.difference_update(
                    signal
                    for signal in _RUNTIME_SURFACE_SIGNALS & active
                    if not _is_runtime_surface_evidence(evidence.get(signal))
                )
            return active
        if isinstance(doc.get("signals"), list):
            return {str(signal) for signal in doc["signals"]}
        return {k for k, v in doc.items() if v}
    if isinstance(doc, list):
        return set(doc)
    return None


def _effective_registration_signal(signals: set[str] | None, output_dir: Path) -> set[str] | None:
    """Overlay the late deterministic registration verdict onto recon signals.

    The recon sidecar is produced before architecture curates attack surface,
    while ``analyzers/detect_open_registration.py`` evaluates the canonical attack surface
    plus the complete route inventory during the deterministic tail. Abuse
    matching runs after that tail, so the later boolean is authoritative when
    present. Missing YAML/meta leaves the earlier signal unchanged; an explicit
    false removes a stale recon true as well as true adding a missed signal.
    """
    path = output_dir / "threat-model.yaml"
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return signals
    if not isinstance(document, dict):
        return signals
    meta = document.get("meta")
    if not isinstance(meta, dict):
        return signals
    value = meta.get("open_user_registration")
    if not isinstance(value, bool):
        return signals
    effective = set(signals or ())
    if value:
        effective.add("has_open_self_registration")
    else:
        effective.discard("has_open_self_registration")
    return effective


def _scan_case_config(output_dir: Path) -> tuple[list[Path], set[str]]:
    """Read optional per-scan case files and ID filters from run config."""
    try:
        cfg = json.loads((output_dir / ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], set()
    files = [Path(p) for p in (cfg.get("abuse_case_files") or []) if isinstance(p, str)]
    ids = {str(cid) for cid in (cfg.get("only_abuse_case_ids") or []) if isinstance(cid, str)}
    return files, ids


def _assessment_depth(output_dir: Path) -> str:
    try:
        cfg = json.loads((output_dir / ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "standard"
    depth = cfg.get("assessment_depth") if isinstance(cfg, dict) else None
    return depth if depth in {"quick", "standard", "thorough"} else "standard"


def apply_descriptive_limits(matches: list[dict], requested: set[str], depth: str, limits: dict[str, int]) -> None:
    """Bound model work on descriptive candidates; record every omission.

    Explicitly requested cases run at every depth up to their own limit.
    Optional ones run from standard depth up to the depth's limit, strongest
    preselection evidence first. An omitted candidate becomes
    ``not_performed`` with its reason, so it is reported rather than lost.
    """
    optional_cap = {
        "quick": 0,
        "standard": limits["descriptive_candidates_standard"],
        "thorough": limits["descriptive_candidates_thorough"],
    }[depth]
    explicit_cap = limits["descriptive_candidates_explicit"]
    for match in matches:
        # A request is answered even when preselection found nothing: the
        # verifier then binds the case without a preselected file set.
        if (
            match.get("kind") == "descriptive"
            and match["abuse_case_id"] in requested
            and match.get("structural_verdict") == "not_applicable"
        ):
            match["structural_verdict"] = "candidate"
            match["reason"] = f"explicitly requested; preselection found no match ({match.get('reason')})"
    candidates = [m for m in matches if m.get("kind") == "descriptive" and m.get("structural_verdict") == "candidate"]
    ranked = sorted(
        candidates,
        key=lambda m: (
            -len(m.get("related_finding_ids") or []),
            -len(m.get("preselected_sources") or []),
            m["abuse_case_id"],
        ),
    )
    used = {"explicit": 0, "optional": 0}
    for match in ranked:
        match["requested"] = match["abuse_case_id"] in requested
        kind = "explicit" if match["requested"] else "optional"
        cap = explicit_cap if match["requested"] else optional_cap
        if used[kind] < cap:
            used[kind] += 1
            continue
        match["structural_verdict"] = "not_performed"
        if match["requested"]:
            match["reason"] = f"exceeds the limit of {explicit_cap} explicitly requested business cases per run"
        elif depth == "quick":
            match["reason"] = "quick depth verifies business cases only on explicit request"
        else:
            match["reason"] = f"exceeds the limit of {optional_cap} business cases at {depth} depth"


def _candidate_priority(case_match: dict, findings_by_id: dict[str, dict]) -> tuple:
    """Prioritize verification from matched evidence, retaining every candidate.

    A source-only probe uses its declared classification provisionally. A
    template never overrides an existing finding or rates an unmatched step.
    """
    definitions = {step.get("step"): step for step in (case_match.get("case") or {}).get("chain") or []}
    findings = []
    for step in case_match.get("step_matches") or []:
        finding = findings_by_id.get(step.get("matched_finding_id"))
        if finding:
            findings.append(finding)
        elif step.get("match_basis") == "source_probe" and step.get("matched"):
            classification = (definitions.get(step.get("step")) or {}).get("finding")
            if classification:
                provisional = dict(classification)
                normalize_risks([provisional])
                findings.append(provisional)
    return (
        *abuse_case_priority(findings),
        case_match.get("structural_verdict") != "candidate",
        case_match.get("abuse_case_id") or "",
    )


def load_routes(out_dir: Path) -> list[dict] | None:
    """Routes of the run's route inventory with a path and handler file; None when the inventory is absent."""
    try:
        document = json.loads((out_dir / ".route-inventory.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    routes = document.get("routes") if isinstance(document, dict) else None
    if not isinstance(routes, list):
        return None
    return [
        route
        for route in routes
        if isinstance(route, dict) and isinstance(route.get("path"), str) and isinstance(route.get("handler_file"), str)
    ]


def cmd_match(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    findings_path = Path(args.findings) if args.findings else out_dir / ".threats-merged.json"
    # Evidence verification runs before abuse matching. A refuted candidate is
    # no longer a finding and must not bind a later chain step merely because
    # the pre-verification merged register retains it for auditability.
    findings = matchable_findings(load_findings(findings_path))
    normalize_risks(findings)
    repo_root = Path(args.repo_root) if getattr(args, "repo_root", None) else None
    signals = _load_signals(args.signals, repo_root=repo_root)
    signals = _effective_registration_signal(signals, out_dir)

    profile = None
    profile_dir = None
    if args.org_profile:
        rac = _rac()
        p = Path(args.org_profile)
        profile = rac._load_yaml(p)
        profile_dir = p.parent
    extra_case_files, only_ids = _scan_case_config(out_dir)
    origins: dict[str, str] = {}
    rac = _rac()
    limits = rac.load_limits()
    cases, errors, rejected = rac.resolve_abuse_case_sources(
        profile, profile_dir, PLUGIN_ROOT, repo_root, extra_case_files=extra_case_files, origins=origins
    )
    for item in rejected:
        sys.stderr.write(f"REJECTED: {item['path']}: {item['reason']}\n")
    if errors:
        for e in errors:
            sys.stderr.write(f"ERROR: {e}\n")
        return 1

    unknown_ids = sorted(only_ids - {c.get("id") for c in cases})
    if unknown_ids:
        for cid in unknown_ids:
            sys.stderr.write(f"ERROR: selected abuse-case id {cid!r} is not active\n")
        return 1
    if only_ids:
        cases = [c for c in cases if c.get("id") in only_ids]
    max_files = limits["descriptive_source_files"]
    routes = load_routes(out_dir)
    matches = [
        match_case(c, findings, signals, repo_root=repo_root, max_descriptive_files=max_files, routes=routes)
        for c in cases
    ]
    findings_by_id = {_finding_id(finding): finding for finding in findings}
    matches.sort(key=lambda match: _candidate_priority(match, findings_by_id))
    requested = {cid for cid, origin in origins.items() if origin == "explicit"} | only_ids
    apply_descriptive_limits(matches, requested, _assessment_depth(out_dir), limits)
    result = {"schema_version": 1, "matches": matches}
    if rejected:
        result["rejected_case_files"] = rejected
    (out_dir / ".abuse-case-matches.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    n_cand = sum(1 for m in matches if m["structural_verdict"] in ("candidate", "partial_candidate"))
    sys.stderr.write(f"MATCH: {len(matches)} cases, {n_cand} candidate(s)\n")
    return 0


def cmd_list_candidates(args: argparse.Namespace) -> int:
    matches_path = Path(args.output_dir) / ".abuse-case-matches.json"
    if not matches_path.exists():
        return 0
    doc = json.loads(matches_path.read_text(encoding="utf-8"))
    for m in doc.get("matches", []):
        if m.get("structural_verdict") in ("candidate", "partial_candidate"):
            print(m["abuse_case_id"])
    return 0


def cmd_list_inconclusive(args: argparse.Namespace) -> int:
    """Print AC-IDs whose chain verdict is `inconclusive` and that the matcher
    rated a real candidate — i.e. worth a second look by a stronger model.

    Run AFTER `finalize` (needs `chain_verdict`). Output is the escalation
    work-list for the skill's sonnet re-verify pass. Capped at `--max` so the
    escalation cost stays bounded; the cap drop is logged to stderr. A chain
    with a `refuted` step is settled — a re-read of the same mismatch cannot
    change it, and that step caps the chain whatever its other steps show — so
    it is not listed (AC-6).
    """
    out_dir = Path(args.output_dir)
    verdicts_path = out_dir / ".abuse-case-verdicts.json"
    if not verdicts_path.exists():
        return 0
    try:
        vdoc = json.loads(verdicts_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    verdicts = vdoc.get("verdicts") if isinstance(vdoc, dict) else vdoc

    # Only escalate cases the matcher considered plausible (candidate /
    # partial_candidate) — don't spend a strong model re-checking weak matches.
    candidates: set[str] = set()
    matches_path = out_dir / ".abuse-case-matches.json"
    if matches_path.exists():
        try:
            mdoc = json.loads(matches_path.read_text(encoding="utf-8"))
            candidates = {
                m["abuse_case_id"]
                for m in mdoc.get("matches", [])
                if m.get("structural_verdict") in ("candidate", "partial_candidate")
            }
        except (OSError, json.JSONDecodeError, KeyError):
            candidates = set()

    def open_work(verdict: dict) -> bool:
        steps = {s.get("verdict") for s in verdict.get("step_verdicts") or [] if isinstance(s, dict)}
        return _REFUTED not in steps

    inconclusive = sorted(
        v.get("abuse_case_id")
        for v in (verdicts or [])
        if v.get("chain_verdict") == _INCONCLUSIVE
        and v.get("abuse_case_id")
        and (not candidates or v.get("abuse_case_id") in candidates)
        and open_work(v)
    )

    cap = max(0, int(getattr(args, "max", 5) or 0))
    if cap and len(inconclusive) > cap:
        sys.stderr.write(
            f"ESCALATE: {len(inconclusive)} inconclusive, capping to {cap} (dropped: {', '.join(inconclusive[cap:])})\n"
        )
        inconclusive = inconclusive[:cap]

    for cid in inconclusive:
        print(cid)
    return 0


_EXCERPT_WINDOW = 3
_DECIDING_VERDICTS = frozenset({_CONFIRMED, _BLOCKED, _REFUTED})


def _configured_repo_root(output_dir: Path | None) -> Path | None:
    if output_dir is None:
        return None
    try:
        cfg = json.loads((output_dir / ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    root = cfg.get("repo_root") if isinstance(cfg, dict) else None
    return Path(root) if isinstance(root, str) and root else None


def _evidence_problem(evidence: object, repo_root: Path | None) -> str | None:
    """Return why a step's evidence cannot be admitted, or None when it can.

    Admitted evidence names a runtime source file inside the repository and
    an excerpt that occurs within a few lines of the cited line.
    """
    if repo_root is None:
        return "repository root unavailable"
    if not isinstance(evidence, dict):
        return "no evidence"
    file, line, excerpt = evidence.get("file"), evidence.get("line"), evidence.get("excerpt")
    if not isinstance(file, str) or _safe_repo_glob(file) is None or not _is_runtime_surface_evidence(file):
        return "file is not a runtime source path inside the repository"
    if type(line) is not int or line < 1:
        return "no positive line"
    if not isinstance(excerpt, str) or not excerpt.strip():
        return "no excerpt"
    root = repo_root.resolve()
    path = root / file
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        return "file does not exist inside the repository"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _SOURCE_PROBE_MAX_BYTES:
        return "file is not an admissible regular file"
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    window = " ".join(lines[max(0, line - 1 - _EXCERPT_WINDOW) : line + _EXCERPT_WINDOW])
    if " ".join(excerpt.split()) not in " ".join(window.split()):
        return f"excerpt does not occur near {file}:{line}"
    return None


def admit_descriptive_evidence(verdict: dict, step_count: int, repo_root: Path | None) -> None:
    """Downgrade descriptive step verdicts whose evidence is not in the code.

    A descriptive case has no deterministic binding, so the verifier's cited
    location is the binding. A deciding verdict (confirmed, blocked, refuted)
    stands only on an excerpt found at the cited source line; otherwise the
    step becomes a decided ``inconclusive`` and keeps the rejected citation for
    audit. Steps outside the case's chain are dropped.
    """
    kept = []
    for step in verdict.get("step_verdicts") or []:
        if not isinstance(step, dict) or type(step.get("step")) is not int or not 1 <= step["step"] <= step_count:
            continue
        if step.get("verdict") in _DECIDING_VERDICTS:
            problem = _evidence_problem(step.get("evidence"), repo_root)
            if problem:
                step["rejected_evidence"] = step.get("evidence")
                step["evidence"] = None
                step["verdict"] = _INCONCLUSIVE
                step["reason"] = f"evidence not admitted ({problem}): {str(step.get('reason') or '')[:200]}"
        kept.append(step)
    verdict["step_verdicts"] = kept


def cmd_finalize(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir) if args.output_dir else None
    matches_path = Path(args.matches) if args.matches else (out_dir / ".abuse-case-matches.json")
    verdicts_path = Path(args.verdicts) if args.verdicts else (out_dir / ".abuse-case-verdicts.json")
    matches = {m["abuse_case_id"]: m for m in json.loads(matches_path.read_text(encoding="utf-8")).get("matches", [])}
    vdoc = json.loads(verdicts_path.read_text(encoding="utf-8"))
    verdicts = vdoc.get("verdicts") if isinstance(vdoc, dict) else vdoc

    repo_root = Path(args.repo_root) if getattr(args, "repo_root", None) else _configured_repo_root(out_dir)
    for v in verdicts:
        cid = v.get("abuse_case_id")
        case_match = matches.get(cid, {"step_matches": []})
        if case_match.get("kind") == "descriptive":
            admit_descriptive_evidence(v, len(case_match.get("step_matches") or []), repo_root)
        v["chain_verdict"] = finalize_verdict(case_match, v.get("step_verdicts") or [])

    out = {"schema_version": 1, "verdicts": verdicts}
    target = verdicts_path
    target.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic abuse-case matcher / finalizer.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("match", help="match abuse cases against findings")
    m.add_argument("--output-dir", required=True)
    m.add_argument("--findings", help="path to .threats-merged.json (default: <output-dir>/.threats-merged.json)")
    m.add_argument("--org-profile", default=None)
    m.add_argument(
        "--repo-root",
        default=None,
        help="target repo root; loads <repo>/docs/security/abuse-cases/ and <repo>/.appsec/abuse-cases/",
    )
    m.add_argument("--signals", default=None, help="recon signals json (optional)")
    m.set_defaults(func=cmd_match)

    lc = sub.add_parser("list-candidates", help="print candidate ids")
    lc.add_argument("--output-dir", required=True)
    lc.set_defaults(func=cmd_list_candidates)

    fz = sub.add_parser("finalize", help="fold step verdicts into chain verdicts")
    fz.add_argument("--output-dir", default=None)
    fz.add_argument("--matches", default=None)
    fz.add_argument("--verdicts", default=None)
    fz.add_argument("--repo-root", default=None, help="target repo root (default: repo_root in .skill-config.json)")
    fz.set_defaults(func=cmd_finalize)

    li = sub.add_parser(
        "list-inconclusive", help="print candidate ids whose chain verdict is inconclusive (escalation work-list)"
    )
    li.add_argument("--output-dir", required=True)
    li.add_argument("--max", type=int, default=5, help="cap the escalation work-list (default 5; 0 = no cap)")
    li.set_defaults(func=cmd_list_inconclusive)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
