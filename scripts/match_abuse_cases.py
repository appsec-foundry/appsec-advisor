#!/usr/bin/env python3
"""match_abuse_cases.py — deterministic abuse-case matcher + verdict finalizer.

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

import argparse
import importlib.util
import json
import re
import sys
from functools import lru_cache
from pathlib import Path

import scan_excludes
import yaml
from validate_intermediate import validate_recon_signals

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def _rac():
    spec = importlib.util.spec_from_file_location(
        "resolve_abuse_cases", Path(__file__).resolve().parent / "resolve_abuse_cases.py"
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
    return [finding for finding in findings if finding.get("evidence_check") != "refuted"]


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
# matcher therefore requires an accompanying code or mechanism phrase from the
# case probe before dispatching an expensive verifier for these CWEs.
_CONTEXT_DEPENDENT_CWES = frozenset({"284", "287", "347", "384"})

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
) -> dict:
    """Match one chain step to its best-fitting finding.

    Scoring (not first-match): every sink pattern that hits a finding contributes
    its ``_pattern_specificity`` weight, but a CWE pattern earns its strong bonus
    only when it matches the finding's OWN ``cwe`` field (not an incidental CWE
    mention in prose). The highest-scoring finding wins; ties prefer a finding not
    already consumed by an earlier step in the same chain (``exclude_ids``) so a
    two-step chain does not degenerate into the same finding twice; final tie-break
    is finding list order (deterministic).
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
        if score > top_score:
            top_score = score
            weak_tie_ids = {fid} if weak else set()
        elif score == top_score and weak:
            weak_tie_ids.add(fid)
        # Maximise: score, the step's own CWE, real mechanism evidence, then
        # prefer a not-yet-consumed finding, then earliest.
        key = (score, exact_cwe, has_non_cwe_match, fid not in exclude_ids, -idx)
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


def match_case(case: dict, findings: list[dict], signals: set[str] | None, repo_root: Path | None = None) -> dict:
    applicable, unmet_signals, unmet_paths = _scope_status(case, signals, repo_root)
    # Thread consumed finding ids so a later step prefers a distinct finding —
    # a two-step chain (IDOR → mass-assignment) must not collapse to one finding.
    step_matches = []
    consumed: set[str] = set()
    for s in case.get("chain") or []:
        m = match_step(s, findings, exclude_ids=consumed, repo_root=repo_root if applicable else None)
        if m.get("matched") and m.get("matched_finding_id"):
            consumed.add(m["matched_finding_id"])
        step_matches.append(m)
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
_INCONCLUSIVE = "inconclusive"


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
    any ASSESSED step inconclusive                    -> inconclusive

    ``fully_viable`` is a positive claim of end-to-end exploitability, so it
    requires every step the verifier actually assessed to be ``confirmed`` —
    not merely the ``required`` subset. See the inconclusive cap below.
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
    if any(v == _INCONCLUSIVE for v in verdicts):
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
    # while aggregate_run_issues.py concurrently flagged the same chain as "not
    # verified end-to-end". A chain whose payoff was never established must not
    # carry a positive viability claim.
    #
    # `inconclusive` loses nothing: §9 still renders the case with every step and
    # its individual verdict, `_combined_risk` simply stops applying the
    # fully-viable severity escalation, and triage_compute_ranking stops
    # elevating the member findings off an unproven chain.
    if any(v.get("verdict") == _INCONCLUSIVE for v in step_verdicts):
        return "inconclusive"
    confirmed = [v == _CONFIRMED for v in verdicts]
    if all(confirmed):
        return "partially_blocked" if any_control else "fully_viable"
    # mix of confirmed + blocked, none inconclusive
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
    while ``detect_open_registration.py`` evaluates the canonical attack surface
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


def cmd_match(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    findings_path = Path(args.findings) if args.findings else out_dir / ".threats-merged.json"
    # Evidence verification runs before abuse matching. A refuted candidate is
    # no longer a finding and must not bind a later chain step merely because
    # the pre-verification merged register retains it for auditability.
    findings = matchable_findings(load_findings(findings_path))
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
    cases, errors = _rac().resolve_abuse_cases(
        profile, profile_dir, PLUGIN_ROOT, repo_root, extra_case_files=extra_case_files
    )
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
    matches = [match_case(c, findings, signals, repo_root=repo_root) for c in cases]
    result = {"schema_version": 1, "matches": matches}
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
    escalation cost stays bounded; the cap drop is logged to stderr.
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

    inconclusive = sorted(
        v.get("abuse_case_id")
        for v in (verdicts or [])
        if v.get("chain_verdict") == _INCONCLUSIVE
        and v.get("abuse_case_id")
        and (not candidates or v.get("abuse_case_id") in candidates)
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


def cmd_finalize(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir) if args.output_dir else None
    matches_path = Path(args.matches) if args.matches else (out_dir / ".abuse-case-matches.json")
    verdicts_path = Path(args.verdicts) if args.verdicts else (out_dir / ".abuse-case-verdicts.json")
    matches = {m["abuse_case_id"]: m for m in json.loads(matches_path.read_text(encoding="utf-8")).get("matches", [])}
    vdoc = json.loads(verdicts_path.read_text(encoding="utf-8"))
    verdicts = vdoc.get("verdicts") if isinstance(vdoc, dict) else vdoc

    for v in verdicts:
        cid = v.get("abuse_case_id")
        case_match = matches.get(cid, {"step_matches": []})
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
    m.add_argument("--repo-root", default=None, help="target repo root; loads <repo>/.appsec/abuse-cases/*.yaml")
    m.add_argument("--signals", default=None, help="recon signals json (optional)")
    m.set_defaults(func=cmd_match)

    lc = sub.add_parser("list-candidates", help="print candidate ids")
    lc.add_argument("--output-dir", required=True)
    lc.set_defaults(func=cmd_list_candidates)

    fz = sub.add_parser("finalize", help="fold step verdicts into chain verdicts")
    fz.add_argument("--output-dir", default=None)
    fz.add_argument("--matches", default=None)
    fz.add_argument("--verdicts", default=None)
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
