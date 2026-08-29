#!/usr/bin/env python3
"""Normalize trust boundaries and prepare bounded per-component STRIDE context.

``normalize`` is the sole semantic bridge from provisional/legacy Phase-7 data
and optional repository declarations to the strict v2 sidecar.
``contexts`` derives adjacency candidates only for components that the existing
STRIDE selector already chose; it never expands the dispatch set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import jsonschema
from validate_fragment import fragment_invariant_errors
import yaml
from _atomic_io import atomic_write_json
from reclassify_components import (  # shared path-ownership resolver — see _evidence_owners
    _glob_specificity as _rc_glob_specificity,
)
from reclassify_components import (
    _glob_to_regex as _rc_glob_to_regex,
)
from reserve_ids import ensure_counter_at_least, reserve
from sanitize_perimeter_claims import sanitize_perimeter_prose

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
NORMALIZED_SCHEMA = PLUGIN_ROOT / "schemas" / "fragments" / "trust-boundaries.schema.json"
REPO_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundaries-repo.schema.yaml"
DIAGNOSTICS_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundary-diagnostics.schema.json"
CANDIDATES_SCHEMA = PLUGIN_ROOT / "schemas" / "fragments" / "trust-boundary-candidates.schema.json"
ASSESSMENT_INPUT_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundary-assessment-input.schema.json"
COVERAGE_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundary-coverage.schema.json"
SELECTION_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundary-selection.schema.json"
KINDS = {"network", "process", "identity", "privilege", "tenant", "data-origin", "third-party", "build"}
# `kind` mixes three questions: HOW the crossing happens (network/process),
# WHAT changes across it (identity/privilege/tenant/data-origin) and WHO operates
# the far side (third-party/build). The values are therefore neither disjoint nor
# parallel — an OAuth callback is `identity` AND a network crossing, so the
# analyst has to guess an undocumented precedence. Internally we branch on two
# orthogonal axes instead. `kind` stays the sole authored/wire value (analyst,
# `.appsec/trust-boundaries.yaml`, legacy models, renderer, exports); the axes are
# DERIVED from it in one deterministic place, so there is never a second
# authority to keep in sync and no repo declaration has to be migrated.
SURFACES = {"network", "in-process", "build-pipeline"}
TRANSITIONS = {"identity", "privilege", "tenant", "data-origin", "operator"}
_KIND_AXES: dict[str, tuple[str, tuple[str, ...]]] = {
    "network": ("network", ()),
    "process": ("in-process", ()),
    "identity": ("network", ("identity",)),
    "privilege": ("network", ("privilege",)),
    "tenant": ("network", ("tenant",)),
    "data-origin": ("network", ("data-origin",)),
    "third-party": ("network", ("operator",)),
    "build": ("build-pipeline", ("operator",)),
}
LEGACY_FIELDS = {"controls", "description", "enforcement", "crossing_enforcement", "trust_level", "weakness"}
# Values that name no specific control. Kept as an explicit list rather than a
# schema `pattern`: genericness is not lexical (a pattern banning "code" would
# also reject "OAuth authorization-code exchange"), and a schema rejection would
# fail the whole artifact where dropping the field degrades safely.
_GENERIC_ENFORCEMENT_POINTS = {
    "application",
    "application code",
    "application layer",
    "application logic",
    "auth",
    "authentication",
    "authorization",
    "backend",
    "code",
    "controller",
    "express",
    "express app",
    "framework",
    "handler",
    "middleware",
    "network",
    "route handler",
    "router",
    "server",
    "service",
    "system",
    "validation",
    "web server",
}
NEUTRAL_LEGACY_ASSUMPTION = "Assumption not recorded in legacy model"
MAX_BOUNDARY_ID = 999_999_999
_ID_RE = re.compile(r"^tb-(\d+)$")
_COMPONENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]+$")
_CANONICAL_ENDPOINT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TRAILING_PAREN_RE = re.compile(r"\s*\([^()]*\)\s*$")
_EXTERNAL_ALIASES = {
    "external",
    "internet",
    "the internet",
    "public internet",
    "outside network",
    "untrusted network",
}


def _read_json(path: Path | None, default: Any = None) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _read_yaml(path: Path | None, default: Any = None) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return default


def _warn(message: str, warnings: list[str]) -> None:
    warnings.append(message)
    print(f"TRUST_BOUNDARY_WARN: {message}", file=sys.stderr)


def _clean_text(value: Any, *, fallback: str, limit: int) -> str:
    text = _CONTROL_RE.sub("", str(value or "")).strip()
    text, _removed = sanitize_perimeter_prose(text)
    text = " ".join(text.split())
    return (text or fallback)[:limit]


def _endpoint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = _CONTROL_RE.sub("", value).strip()
    if not value or len(value) > 128:
        return None
    return value


def _canonical_evidence(repo_root: Path, values: Any, warnings: list[str], label: str) -> list[dict]:
    result: list[dict] = []
    seen: set[tuple[str, int | None]] = set()
    root = repo_root.resolve()
    for raw in values if isinstance(values, list) else []:
        if not isinstance(raw, dict) or not isinstance(raw.get("file"), str):
            _warn(f"{label}: ignored malformed evidence entry", warnings)
            continue
        rel_text = raw["file"].replace("\\", "/").strip()
        rel = Path(rel_text)
        if not rel_text or len(rel_text) > 512 or rel.is_absolute() or ".." in rel.parts or "://" in rel_text:
            _warn(f"{label}: rejected unsafe evidence path {rel_text!r}", warnings)
            continue
        candidate = (root / rel).resolve()
        try:
            canonical_rel = candidate.relative_to(root).as_posix()
        except ValueError:
            _warn(f"{label}: rejected out-of-repository evidence path {rel_text!r}", warnings)
            continue
        if not candidate.is_file():
            _warn(f"{label}: rejected missing/non-regular evidence file {canonical_rel!r}", warnings)
            continue
        line = raw.get("line")
        if line is not None:
            if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                _warn(f"{label}: rejected invalid evidence line for {canonical_rel!r}", warnings)
                continue
            try:
                line_count = sum(1 for _ in candidate.open("r", encoding="utf-8", errors="ignore"))
            except OSError:
                continue
            if line > max(line_count, 1):
                _warn(f"{label}: rejected out-of-range line {line} for {canonical_rel!r}", warnings)
                continue
        key = (canonical_rel, line)
        if key in seen:
            continue
        seen.add(key)
        item = {"file": canonical_rel}
        if line is not None:
            item["line"] = line
        result.append(item)
        if len(result) == 5:
            break
    return result


def _component_rows(sidecar: dict | None, prior: dict | None) -> list[dict]:
    rows = (sidecar or {}).get("components")
    if not isinstance(rows, list):
        rows = (prior or {}).get("components") or []
    return [
        row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and _COMPONENT_ID_RE.fullmatch(row["id"])
    ]


def _component_ids(sidecar: dict | None, prior: dict | None) -> set[str]:
    return {row["id"] for row in _component_rows(sidecar, prior)}


def _endpoint_lookup_key(value: str) -> str:
    """Conservative comparison form; never persisted as a public endpoint."""
    stripped = _TRAILING_PAREN_RE.sub("", value.strip())
    return " ".join(stripped.casefold().split())


def _resolve_endpoint(value: Any, components: dict[str, dict]) -> tuple[str | None, str, list[str]]:
    """Return ``(value, method, candidates)`` for one untrusted endpoint.

    Resolved methods are ``exact_id``, ``external_literal``,
    ``external_alias``, and ``component_name``. An unresolved result preserves
    the bounded raw string for the review catalogue.
    """
    raw = _endpoint(value)
    if raw is None:
        return None, "missing", []
    if raw == "external":
        return "external", "external_literal", []
    if raw in components:
        return raw, "exact_id", []

    key = _endpoint_lookup_key(raw)
    if key in _EXTERNAL_ALIASES or key.startswith("external "):
        return "external", "external_alias", []

    by_name: dict[str, list[str]] = defaultdict(list)
    for cid, row in components.items():
        name = row.get("name")
        if isinstance(name, str) and name.strip():
            by_name[_endpoint_lookup_key(name)].append(cid)
    matches = sorted(set(by_name.get(key, [])))
    if len(matches) == 1:
        return matches[0], "component_name", matches
    return raw, "ambiguous" if matches else "unresolved", matches[:8]


def boundary_endpoints_valid(boundary: dict, component_ids: set[str]) -> bool:
    """Dynamic resolved-row invariant shared by all downstream consumers."""
    if not isinstance(boundary, dict) or boundary.get("resolution_status") != "resolved":
        return False
    allowed = component_ids | {"external"}
    return boundary.get("from") in allowed and boundary.get("to") in allowed


_UNVERIFIED_EVIDENCE_STATES = frozenset({"refuted", "ambiguous"})


def _finding_number(value: Any) -> tuple[int, str]:
    text = str(value or "")
    match = re.search(r"(\d+)$", text)
    return (int(match.group(1)), text) if match else (10**9, text)


def boundary_protected_components(boundary: dict) -> set[str]:
    """Components on the protected side of the crossing.

    `covers_components` records what a consolidation folded into the row and
    carries BOTH endpoints, so the source has to come back out — otherwise
    `express-backend -> sqlite-database` counts its own origin as protected.
    """
    source = boundary.get("from")
    protected = {boundary.get("to"), *(boundary.get("covers_components") or [])}
    protected.discard(source)
    return {str(cid) for cid in protected if cid}


# --------------------------------------------------------------------------- #
# Assumption legs
#
# A trust boundary exists because what crosses it cannot be trusted, so its
# assumption has to state the conditions that resolve that distrust — for an
# inbound crossing: validation, authentication, authorization (user 2026-08-01).
# A one-sentence assumption naming a single mechanism ("expressJwt is
# registered") is a different claim category: the middleware can run while the
# crossing is wide open, and — worse — findings on the legs it does not mention
# have nothing to attach to. juice-shop's tb-1 stated authentication only; its
# authorization findings (F-008 IDOR Critical, F-038, F-039) carried no
# boundary_refs at all.
#
# The vocabulary is derived from the crossing DIRECTION, never from `kind`:
# tb-1 (`network`) and tb-7 (`third-party`) both have `surface: network` and are
# opposite directions, so `kind` cannot discriminate. `from`/`to == external`
# can, and always.
# --------------------------------------------------------------------------- #
INGRESS_LEGS = ("validation", "authentication", "authorization")
EGRESS_LEGS = ("egress-content", "egress-destination", "response-trust")
# An in-process crossing is an enforcement interface. `data-interpretation` is
# the leg tb-4/5/6 already state today ("every query reaches the database
# through parameter binding"); authentication/authorization stay available for
# an internal row that really is a decision point — tb-3, the token
# verification step, is authentication and nothing else. The analyst declares
# the applicable subset; unlike ingress/egress these are NOT auto-synthesized,
# because "every in-process interface has an authorization leg" is false and a
# synthesized one would assert a condition nobody holds.
INTERNAL_LEGS = ("data-interpretation", "authentication", "authorization")
CROSSING_TYPE_LEGS = {"ingress": INGRESS_LEGS, "egress": EGRESS_LEGS, "internal": INTERNAL_LEGS}
# Same budget as the assumption sentence it decomposes.
MAX_LEG_CONDITION = 180
_CWE_LEGS_PATH = PLUGIN_ROOT / "data" / "cwe-boundary-legs.yaml"
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def boundary_crossing_type(boundary: dict) -> str:
    """`ingress` | `egress` | `internal`, from the crossing direction alone.

    A row with `external` on both ends cannot exist (promotion resolves both
    endpoints against the component registry), but if one ever did, treating it
    as ingress is the conservative read: it gets the widest leg vocabulary.
    """
    if not isinstance(boundary, dict):
        return "internal"
    origin = str(boundary.get("from") or "").strip().casefold()
    target = str(boundary.get("to") or "").strip().casefold()
    if origin == "external":
        return "ingress"
    if target == "external":
        return "egress"
    return "internal"


def boundary_leg_vocabulary(boundary: dict) -> tuple[str, ...]:
    """The legs this crossing MAY declare. Anything else is a modelling error."""
    return CROSSING_TYPE_LEGS[boundary_crossing_type(boundary)]


def normalize_assumption_legs(raw: Any, boundary: dict, label: str, warnings: list[str]) -> list[dict]:
    """Validate authored `assumption_legs`; drop what the crossing cannot have.

    Fail-open on the individual leg, like every other optional traceability
    field here: a bad leg is removed and the row survives, because a boundary
    with a wrong leg is still a boundary worth reporting.
    """
    if not isinstance(raw, list):
        return []
    allowed = boundary_leg_vocabulary(boundary)
    legs: list[dict] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            _warn(f"{label}: ignored malformed assumption leg", warnings)
            continue
        name = str(entry.get("leg") or "").strip().casefold()
        if name not in allowed:
            _warn(
                f"{label}: dropped leg {name or '<empty>'!r} — not valid for a {boundary_crossing_type(boundary)} crossing",
                warnings,
            )
            continue
        if name in seen:
            _warn(f"{label}: dropped duplicate leg {name!r}", warnings)
            continue
        seen.add(name)
        condition = _clean_text(entry.get("condition"), fallback="", limit=MAX_LEG_CONDITION)
        legs.append({"leg": name, "condition": condition} if condition else {"leg": name})
    return [leg for name in allowed for leg in legs if leg["leg"] == name]


def boundary_legs(boundary: dict) -> list[dict]:
    """Declared legs, or the synthesized default for a directional crossing.

    Ingress and egress crossings get their full triad synthesized when the row
    declares none: those legs follow from the direction itself — an inbound
    crossing always has to decide what the payload may contain, who is calling
    and what they may do — so naming them asserts nothing the crossing does not
    already imply, and it lets a model authored before legs existed still report
    per-leg verdicts. An internal row gets only what it declares (see
    INTERNAL_LEGS).
    """
    declared = [leg for leg in (boundary.get("assumption_legs") or []) if isinstance(leg, dict) and leg.get("leg")]
    if boundary_crossing_type(boundary) == "internal":
        return declared
    # Directional crossings keep the FULL triad even when the analyst declared
    # only part of it: declaring a leg may add a condition, never remove one.
    # The alternative — declared list wins outright — means an analyst who names
    # `authorization` alone silently deletes validation and authentication from
    # an inbound crossing, which is a worse table than the one before legs
    # existed. Partial authorship must degrade toward more information, not less.
    by_name = {leg["leg"]: leg for leg in declared}
    return [by_name.get(name, {"leg": name}) for name in boundary_leg_vocabulary(boundary)]


@lru_cache(maxsize=1)
def _cwe_leg_map() -> dict[str, frozenset[str]]:
    """`{CWE-89: {validation, data-interpretation}}` — adjacency attribution only.

    Deliberately many-to-many: the crossing type restricts which legs a row has,
    so one CWE can mean "validation" at an ingress row and "data-interpretation"
    at an in-process one without a global tie-break.
    """
    doc = _read_yaml(_CWE_LEGS_PATH, {}) or {}
    mapping: dict[str, set[str]] = {}
    for leg, cwes in (doc.get("legs") or {}).items():
        if not isinstance(cwes, list):
            continue
        for cwe in cwes:
            match = _CWE_RE.search(str(cwe or ""))
            if match:
                mapping.setdefault(match.group(0).upper(), set()).add(str(leg))
    return {cwe: frozenset(legs) for cwe, legs in mapping.items()}


def _legs_for_finding(threat: dict, allowed: Iterable[str]) -> set[str]:
    match = _CWE_RE.search(str(threat.get("cwe") or ""))
    if not match:
        return set()
    return set(_cwe_leg_map().get(match.group(0).upper(), frozenset())) & set(allowed)


def finding_leg_candidates(threat: dict, boundary: dict) -> list[str]:
    """Legs of `boundary` this finding's CWE could bear on, sorted.

    Public because the §8 card names the leg for a single reference while the
    §1 catalogue derives states for the whole row: two callers that must agree,
    so they share one attribution.
    """
    return sorted(_legs_for_finding(threat, {leg["leg"] for leg in boundary_legs(boundary)}))


def boundary_leg_states(boundary: dict, threats: Iterable[dict]) -> list[dict]:
    """Per-leg verdicts -> `[{leg, condition, state, finding_ids}]`.

    An ADDITIONAL view over the same inputs `boundary_assumption_state` reads;
    it deliberately does not feed that function. The row verdict stays the
    authority so a leg-less link — which refutes the row but names no leg —
    can never make the row read "clean" while a link sits on it.

    States, narrower than the row's on purpose:

      * ``refuted``     — a verified linked finding is attributed to this leg.
      * ``unconfirmed`` — no link, but an adjacent finding's CWE maps here. This
        is the tb-2 fix: three CI/CD findings tested that crossing while the row
        reported "none examined this crossing".
      * ``unexamined``  — nothing in this model bears on the leg.

    Attribution of a LINK prefers the analyst's `leg` field and falls back to
    the CWE map. The fallback only chooses WHICH leg an already-evidenced,
    already-rationalized link lands on; it can never manufacture a link, so it
    carries none of the risk that keeps derived adjacency out of `boundary_refs`.
    """
    legs = boundary_legs(boundary)
    if not legs:
        return []
    allowed = [leg["leg"] for leg in legs]
    boundary_id = str(boundary.get("id") or "")
    protected = boundary_protected_components(boundary)
    refuted: dict[str, list[str]] = {name: [] for name in allowed}
    adjacent: dict[str, list[str]] = {name: [] for name in allowed}
    for threat in threats:
        if not isinstance(threat, dict):
            continue
        tid = str(threat.get("id") or "")
        if not tid:
            continue
        verified = threat.get("evidence_check") not in _UNVERIFIED_EVIDENCE_STATES
        links = [
            ref
            for ref in threat.get("boundary_refs") or []
            if isinstance(ref, dict) and str(ref.get("boundary_id") or "") == boundary_id
        ]
        if links and verified and boundary_id:
            authored = {
                str(ref.get("leg") or "").strip().casefold()
                for ref in links
                if str(ref.get("leg") or "").strip().casefold() in refuted
            }
            for name in sorted(authored or _legs_for_finding(threat, allowed)):
                refuted[name].append(tid)
        elif not links and str(threat.get("component") or threat.get("component_id") or "") in protected:
            for name in sorted(_legs_for_finding(threat, allowed)):
                adjacent[name].append(tid)
    result: list[dict] = []
    for leg in legs:
        name = leg["leg"]
        if refuted[name]:
            state, ids = "refuted", refuted[name]
        elif adjacent[name]:
            state, ids = "unconfirmed", adjacent[name]
        else:
            state, ids = "unexamined", []
        entry = {
            "leg": name,
            "state": state,
            "finding_ids": sorted(set(ids), key=_finding_number),
            # Adjacency is reported even when the leg is already refuted. One
            # linked finding says the condition fails somewhere; five unlinked
            # ones bearing on the same leg say it fails systematically, and
            # suppressing them behind the verdict hid exactly that — tb-1's
            # validation leg reported a single `eval` link while path traversal,
            # XXE, SSRF and mass assignment sat behind the same crossing
            # (user 2026-08-01).
            "adjacent_finding_ids": sorted(set(adjacent[name]) - set(ids), key=_finding_number),
        }
        if leg.get("condition"):
            entry["condition"] = leg["condition"]
        result.append(entry)
    return result


def boundary_assumption_state(boundary: dict, threats: Iterable[dict]) -> tuple[str, list[str]]:
    """Does this row's assumption survive the findings? -> (state, finding ids).

    One derivation for two consumers that must never disagree: the §1
    "Assumption & verdict" cell a reader sees, and the boundary state the
    deterministic scoring reads. Each state, and what it means:

      * ``refuted`` — a finding whose own evidence survived verification links
        here, which by §1's definition is an evidence-backed control gap at the
        crossing. Returns the refuting ids.
      * ``unconfirmed`` — no refuter, but findings sit in the components the
        crossing protects: nothing examined this crossing. juice-shop's
        ``external -> ci-cd-pipeline`` declared "job-level secret scoping not
        confirmed" while eight CI/CD findings proved exactly that, none of them
        linked (user 2026-08-01). Returns those adjacent ids — they are NOT links.
      * ``clean`` — findings could have contradicted it and none do.
      * ``not-examined`` — the row protects no component this model knows.

    The ``evidence_check`` gate mirrors the elevation suppression in
    ``triage_compute_ranking._compute_effective``: a finding that could not raise
    a severity must not silently break a boundary either.
    """
    protected = boundary_protected_components(boundary)
    boundary_id = str(boundary.get("id") or "")
    refuters: list[str] = []
    adjacent: list[str] = []
    for threat in threats:
        if not isinstance(threat, dict):
            continue
        tid = str(threat.get("id") or "")
        if not tid:
            continue
        verified = threat.get("evidence_check") not in _UNVERIFIED_EVIDENCE_STATES
        links_here = any(
            isinstance(ref, dict) and str(ref.get("boundary_id") or "") == boundary_id
            for ref in threat.get("boundary_refs") or []
        )
        if links_here and verified and boundary_id:
            refuters.append(tid)
        elif str(threat.get("component") or threat.get("component_id") or "") in protected:
            adjacent.append(tid)
    if refuters:
        return "refuted", sorted(set(refuters), key=_finding_number)
    if not protected:
        return "not-examined", []
    if adjacent:
        return "unconfirmed", sorted(set(adjacent), key=_finding_number)
    return "clean", []


def _boundary_endpoint_shape_valid(boundary: dict) -> bool:
    if not isinstance(boundary, dict) or boundary.get("resolution_status") != "resolved":
        return False
    return all(
        value == "external" or (isinstance(value, str) and _CANONICAL_ENDPOINT_RE.fullmatch(value))
        for value in (boundary.get("from"), boundary.get("to"))
    )


def _axes_for_kind(kind: Any) -> tuple[str, list[str]]:
    """Split a legacy ``kind`` into (surface, transition[]).

    Total over ``KINDS`` and defaulting exactly like the ``kind`` normalization
    itself (unknown -> network), so the derivation can never fail a row.
    """
    surface, transitions = _KIND_AXES.get(kind if isinstance(kind, str) else "", ("network", ()))
    return surface, list(transitions)


def _apply_axes(rows: Iterable[dict]) -> None:
    """(Re-)derive the orthogonal axes after every path that can set ``kind``."""
    for row in rows:
        if isinstance(row, dict):
            row["surface"], row["transition"] = _axes_for_kind(row.get("kind"))


def _clean_enforcement_point(value: Any) -> str | None:
    """Whitespace-normalized enforcement point, or None when it says nothing.

    A generic value is worse than an absent one. Grouping by enforcement point
    deliberately ignores the endpoints (one control can guard several crossings),
    so "application code" pasted onto three candidates would merge boundaries that
    share nothing but a filler string — the silent over-merge the fallback path is
    designed to avoid. Dropping it here routes those candidates back to the
    conservative crossing-based grouping instead.
    """
    if not isinstance(value, str):
        return None
    text = re.sub(r"\s+", " ", value.strip())
    if len(text) < 3 or len(text) > 120:
        return None
    probe = re.sub(r"^(?:the|a|an)\s+", "", text.casefold()).strip(" .-")
    if probe in _GENERIC_ENFORCEMENT_POINTS:
        return None
    return text


_ASSUMPTION_ABSENCE_RE = re.compile(r"^(?:no|none|there\s+is\s+no|there\s+are\s+no|nothing)\b", re.IGNORECASE)
# A leading "no"/"nothing" does NOT make a sentence an absence — the analyst
# spec's own model answer for an outbound crossing is "Nothing attacker-
# controlled reaches the provider unfiltered", and juice-shop's tb-7 uses it
# verbatim. What separates the two is whether the sentence predicates BEHAVIOUR
# ("nothing … reaches", "no request … passes without") or merely asserts that a
# control does not exist ("No outbound content filter or egress allow-list").
# Only the latter is the failure mode. A closed verb set is enough here and is
# far safer than a general parse: an unknown verb costs one warning, never a
# wrongly-suppressed one.
_ASSUMPTION_CONDITION_VERB_RE = re.compile(
    r"\b(?:reach(?:es)?|cross(?:es)?|leav(?:es)?|pass(?:es)?|requir(?:es)?|run(?:s)?|us(?:es)?"
    r"|call(?:s)?|validat(?:es)?|verif(?:ies|y)?|enforc(?:es)?|accept(?:s)?|receiv(?:es)?"
    r"|send(?:s)?|travel(?:s)?|flow(?:s)?|construct(?:s)?|must|only|without|before|unless)\b",
    re.IGNORECASE,
)
_ASSUMPTION_SANCTION_RE = re.compile(
    r"\b(?:intentionally|by\s+design|deliberately|acceptable|accepted\s+risk|expected\s+to\s+be)\b",
    re.IGNORECASE,
)


def _assumption_shape_warnings(assumption: str, enforcement_point: str | None, label: str) -> list[str]:
    """Report an assumption that cannot carry a verdict — never rewrite it.

    The catalogue renders this text under "Assumption & verdict" and prints a
    derived verdict beneath it, which only works if the sentence is one testable
    condition. A real run produced none: fact lists joined by semicolons, a
    restatement of the control the neighbouring cell already names, and — on both
    outbound rows — a description of what is ABSENT, i.e. the opposite of an
    assumption (user 2026-08-01). The contract now says so in the analyst prompt;
    this makes a violation visible in the run issues instead of shipping quietly.

    Warn, do not repair. A machine rewrite of a security condition would invent
    an assertion no analyst made, and a wrong condition is worse than an ugly one.
    """
    issues: list[str] = []
    # One semicolon already joins two conditions into something no single
    # verdict can address: juice-shop tb-1 read "Protected API routes require a
    # verified JWT via expressJwt; unauthenticated routes are intentionally
    # public." — the threshold of two let it through (user 2026-08-01).
    if ";" in assumption:
        issues.append("reads as a fact list, not one condition")
    if _ASSUMPTION_ABSENCE_RE.match(assumption) and not _ASSUMPTION_CONDITION_VERB_RE.search(assumption):
        issues.append("states an absence instead of a condition")
    # Sanctioning the gap: a clause that excuses in advance what the findings
    # then report as a defect. tb-1's "unauthenticated routes are intentionally
    # public" pre-approved exactly what F-040 and F-042 report, which also makes
    # the sentence unfalsifiable — protected routes are protected, and
    # unprotected ones are meant to be.
    if _ASSUMPTION_SANCTION_RE.search(assumption):
        issues.append("sanctions the gap instead of stating a condition")
    control = " ".join((enforcement_point or "").split()).casefold()
    if control and len(control) >= 8 and control in assumption.casefold():
        issues.append("restates enforcement_point")
    return [f"{label}: assumption {issue}" for issue in issues]


def _covered_components(value: Any, components: Iterable[str]) -> list[str]:
    known = set(components)
    return (
        sorted({item for item in value if isinstance(item, str) and item in known}) if isinstance(value, list) else []
    )


def _normalize_row(
    raw: Any,
    *,
    repo_root: Path,
    components: dict[str, dict],
    legacy_input: bool,
    warnings: list[str],
    source: str,
) -> dict | None:
    if not isinstance(raw, dict):
        _warn("ignored non-object boundary row", warnings)
        return None
    name = _clean_text(raw.get("name"), fallback="Unnamed trust boundary", limit=100)
    label = _clean_text(raw.get("id") or raw.get("key") or name, fallback=name, limit=100)
    from_ep, from_method, from_candidates = _resolve_endpoint(raw.get("from"), components)
    to_ep, to_method, to_candidates = _resolve_endpoint(raw.get("to"), components)
    kind = raw.get("kind") if raw.get("kind") in KINDS else "network"
    assumption_raw = raw.get("assumption")
    is_legacy = legacy_input or bool(LEGACY_FIELDS.intersection(raw))
    assumption = _clean_text(
        assumption_raw,
        fallback=NEUTRAL_LEGACY_ASSUMPTION if is_legacy else "Trust assumption requires review",
        limit=240,
    )
    evidence = _canonical_evidence(repo_root, raw.get("evidence"), warnings, label)
    sources = raw.get("sources") if isinstance(raw.get("sources"), list) else []
    sources = [s for s in sources if s in {"detected", "repo-declared", "legacy"}]
    required_source = "legacy" if is_legacy else source
    if required_source not in sources:
        sources.append(required_source)
    confidence = raw.get("confidence") if raw.get("confidence") in {"confirmed", "inferred", "unknown"} else "inferred"
    if is_legacy and not assumption_raw:
        confidence = "unknown"
    elif source == "repo-declared" and "detected" not in sources:
        confidence = "inferred"
    elif confidence == "confirmed" and (not evidence or "detected" not in sources):
        confidence = "inferred"
    valid_from = from_ep == "external" or from_ep in components
    valid_to = to_ep == "external" or to_ep in components
    resolution = "resolved" if valid_from and valid_to else "unresolved"
    resolution_details: list[dict] = []
    if resolution == "unresolved":
        _warn(f"{label}: unresolved endpoint(s) from={from_ep!r} to={to_ep!r}", warnings)
        authored_resolved = raw.get("resolution_status") == "resolved"
        for side, raw_value, valid, method, candidates in (
            ("from", raw.get("from"), valid_from, from_method, from_candidates),
            ("to", raw.get("to"), valid_to, to_method, to_candidates),
        ):
            if valid:
                continue
            bounded_raw = _endpoint(raw_value)
            resolution_details.append(
                {
                    "code": "invalid_resolved_endpoint" if authored_resolved else "unresolved_endpoint",
                    "side": side,
                    "raw_value": bounded_raw or "",
                    "reason": {
                        "missing": "endpoint is missing or outside the 128-character bound",
                        "ambiguous": "endpoint matches more than one component name",
                        "unresolved": "no exact component name or explicit external marker",
                    }.get(method, "endpoint does not satisfy the canonical contract"),
                    "candidates": candidates,
                }
            )
    if LEGACY_FIELDS.intersection(raw):
        _warn(f"{label}: discarded legacy fields {sorted(LEGACY_FIELDS.intersection(raw))}", warnings)
    row: dict[str, Any] = {
        "name": name,
        "kind": kind,
        "assumption": assumption,
        "evidence": evidence,
        "confidence": confidence,
        "resolution_status": resolution,
        "sources": list(dict.fromkeys(sources)),
    }
    if from_ep:
        row["from"] = from_ep
    if to_ep:
        row["to"] = to_ep
    # Provenance and consolidation record. `enforcement_point` used to be dropped
    # at promotion, which left the merge decision unauditable in the finished
    # model and unrecoverable on the next run; `confidence_basis` separates an
    # analyst's `confirmed` from a deterministically upgraded one; and
    # `covers_components` is what lets a finding in a folded-in component still
    # reference the boundary that now names its deployable.
    point = _clean_enforcement_point(raw.get("enforcement_point"))
    if point:
        row["enforcement_point"] = point
    for issue in _assumption_shape_warnings(assumption, point, label):
        _warn(issue, warnings)
    # Legs decompose the assumption into the conditions the crossing actually
    # has to deliver. Validated against the direction-derived vocabulary, so a
    # `response-trust` leg cannot appear on an inbound row.
    legs = normalize_assumption_legs(raw.get("assumption_legs"), row, label, warnings)
    if legs:
        row["assumption_legs"] = legs
    if raw.get("confidence_basis") in {"analyst", "route-evidence"} and confidence == "confirmed":
        row["confidence_basis"] = raw["confidence_basis"]
    covers = _covered_components(raw.get("covers_components"), components)
    if len(covers) > 1:
        row["covers_components"] = covers[:24]
    if resolution_details:
        row["_resolution_details"] = resolution_details
    key = raw.get("declaration_key") or (raw.get("key") if source == "repo-declared" else None)
    if isinstance(key, str) and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", key) and len(key) <= 80:
        row["declaration_key"] = key
    authored_id = raw.get("id")
    if isinstance(authored_id, str) and _ID_RE.fullmatch(authored_id):
        row["_authored_id"] = authored_id
    # A prior normalized sidecar is a trusted cached artifact, not fresh LLM
    # authorship. This marker enables idempotent re-normalization.
    if (
        not legacy_input
        and raw.get("resolution_status") in {"resolved", "unresolved", "conflicted"}
        and isinstance(authored_id, str)
    ):
        row["_normalized_id"] = authored_id
    return row


def _load_declarations(
    repo_root: Path, components: dict[str, dict], warnings: list[str]
) -> tuple[list[dict], str | None]:
    path = repo_root / ".appsec" / "trust-boundaries.yaml"
    if not path.is_file():
        return [], None
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        _warn(f"rejected complete repository declaration input {path}: {exc}", warnings)
        return [], None
    fingerprint = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    try:
        data = yaml.safe_load(raw_bytes) or {}
        schema = yaml.safe_load(REPO_SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(data)
        keys = [row.get("key") for row in data.get("boundaries", []) if isinstance(row, dict)]
        if len(keys) != len(set(keys)):
            raise jsonschema.ValidationError("boundaries[].key values must be unique")
    except (OSError, yaml.YAMLError, jsonschema.ValidationError) as exc:
        _warn(f"rejected complete repository declaration input {path}: {exc}", warnings)
        return [], fingerprint
    rows = [
        row
        for raw in data.get("boundaries", [])
        if (
            row := _normalize_row(
                raw,
                repo_root=repo_root,
                components=components,
                legacy_input=False,
                warnings=warnings,
                source="repo-declared",
            )
        )
    ]
    return rows, fingerprint


def _merge_evidence(left: list[dict], right: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for item in [*left, *right]:
        key = (item.get("file"), item.get("line"))
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out[:5]


def _merge_declarations(
    detected: list[dict],
    declared: list[dict],
    prior_rows: list[dict],
    warnings: list[str],
) -> list[dict]:
    rows = deepcopy(detected)
    for declaration in declared:
        key = declaration.get("declaration_key")
        keyed = [r for r in rows if r.get("declaration_key") == key] if key else []
        if key and not keyed:
            prior_keyed = [row for row in prior_rows if isinstance(row, dict) and row.get("declaration_key") == key]
            if len(prior_keyed) == 1:
                prior = prior_keyed[0]
                prior_exact = [
                    row
                    for row in rows
                    if (row.get("from"), row.get("to"), row.get("name", "").casefold())
                    == (prior.get("from"), prior.get("to"), str(prior.get("name", "")).casefold())
                ]
                prior_endpoint = [
                    row for row in rows if (row.get("from"), row.get("to")) == (prior.get("from"), prior.get("to"))
                ]
                inherited = (
                    prior_exact[0] if len(prior_exact) == 1 else prior_endpoint[0] if len(prior_endpoint) == 1 else None
                )
                if inherited is not None:
                    inherited["declaration_key"] = key
                    keyed = [inherited]
        exact_name = [
            r
            for r in rows
            if (r.get("from"), r.get("to"), r.get("name").casefold())
            == (declaration.get("from"), declaration.get("to"), declaration.get("name").casefold())
        ]
        endpoint = [r for r in rows if (r.get("from"), r.get("to")) == (declaration.get("from"), declaration.get("to"))]
        target = (
            keyed[0]
            if len(keyed) == 1
            else exact_name[0]
            if len(exact_name) == 1
            else endpoint[0]
            if len(endpoint) == 1
            else None
        )
        if (
            keyed
            and target
            and (target.get("from"), target.get("to")) != (declaration.get("from"), declaration.get("to"))
        ):
            target["resolution_status"] = "conflicted"
            target["sources"] = list(dict.fromkeys([*target["sources"], "repo-declared"]))
            declaration["resolution_status"] = "conflicted"
            detail = {
                "code": "conflicted_boundary",
                "side": "both",
                "raw_value": "",
                "reason": "repository declaration conflicts with detected or prior canonical endpoints",
                "candidates": [],
            }
            target.setdefault("_resolution_details", []).append(deepcopy(detail))
            declaration.setdefault("_resolution_details", []).append(deepcopy(detail))
            _warn(f"declaration {key!r} conflicts with detected/prior endpoints; retained both rows", warnings)
            rows.append(declaration)
            continue
        if target is None:
            rows.append(declaration)
            continue
        target["name"] = declaration["name"]
        target["kind"] = declaration["kind"]
        target["assumption"] = declaration["assumption"]
        target["evidence"] = _merge_evidence(target["evidence"], declaration["evidence"])
        target["sources"] = list(dict.fromkeys([*target["sources"], "repo-declared"]))
        target["declaration_key"] = key
        # Declaration prose/evidence cannot self-confirm. Existing independently
        # detected confirmation may survive.
        if "detected" not in target["sources"]:
            target["confidence"] = "inferred"
    return rows


def _compatible(left: dict, right: dict) -> bool:
    for field in ("from", "to"):
        if left.get(field) and right.get(field) and left.get(field) != right.get(field):
            return False
    return True


def _numeric_id(value: Any) -> int:
    match = _ID_RE.fullmatch(str(value or ""))
    return int(match.group(1)) if match else 0


def _assign_ids(rows: list[dict], prior_rows: list[dict], output_dir: Path, warnings: list[str]) -> None:
    trusted_prior = [r for r in prior_rows if isinstance(r, dict) and _ID_RE.fullmatch(str(r.get("id") or ""))]
    max_prior = max((_numeric_id(r.get("id")) for r in trusted_prior), default=0)
    ensure_counter_at_least(output_dir, "trust_boundary", max_prior + 1)
    prior_by_id = {r["id"]: r for r in trusted_prior}
    prior_by_key: dict[str, list[dict]] = defaultdict(list)
    prior_by_exact: dict[tuple, list[dict]] = defaultdict(list)
    prior_by_endpoint: dict[tuple, list[dict]] = defaultdict(list)
    for prior in trusted_prior:
        if prior.get("declaration_key"):
            prior_by_key[prior["declaration_key"]].append(prior)
        prior_by_exact[(prior.get("from"), prior.get("to"), str(prior.get("name", "")).casefold())].append(prior)
        prior_by_endpoint[(prior.get("from"), prior.get("to"))].append(prior)
    current_endpoint_counts = Counter((r.get("from"), r.get("to")) for r in rows)
    used: set[str] = set()
    for row in rows:
        candidates: list[dict] = []
        key = row.get("declaration_key")
        if key and len(prior_by_key[key]) == 1:
            candidates = prior_by_key[key]
        authored = row.pop("_authored_id", None)
        normalized = row.pop("_normalized_id", None)
        if not candidates and authored in prior_by_id and _compatible(row, prior_by_id[authored]):
            candidates = [prior_by_id[authored]]
        if not candidates:
            candidates = prior_by_exact[(row.get("from"), row.get("to"), str(row.get("name", "")).casefold())]
        if not candidates:
            endpoint_key = (row.get("from"), row.get("to"))
            prior_endpoint = prior_by_endpoint[endpoint_key]
            if len(prior_endpoint) == 1 and current_endpoint_counts[endpoint_key] == 1:
                candidates = prior_endpoint
        chosen = next((p for p in candidates if p["id"] not in used and _compatible(row, p)), None)
        if chosen:
            row["id"] = chosen["id"]
            used.add(chosen["id"])
            continue
        # Idempotence for an already normalized cached sidecar when no separate
        # prior YAML is available. It is accepted only if unique and advances
        # the shared counter; fresh LLM rows lack the deterministic marker.
        if normalized and _ID_RE.fullmatch(normalized) and normalized not in used:
            row["id"] = normalized
            used.add(normalized)
            ensure_counter_at_least(output_dir, "trust_boundary", _numeric_id(normalized) + 1)
            continue
        if candidates:
            _warn(f"ambiguous prior identity for {row.get('name')!r}; allocated a new ID", warnings)
        new_id = reserve(output_dir, "trust_boundary", 1)[0]
        row["id"] = new_id
        used.add(new_id)


def _prior_boundaries(prior_model: Path | None) -> tuple[dict | None, list[dict]]:
    prior = _read_yaml(prior_model, {}) if prior_model else {}
    if not isinstance(prior, dict):
        return None, []
    rows = prior.get("trust_boundaries")
    return prior, rows if isinstance(rows, list) else []


def _canonicalize_prior_rows(rows: list[dict], components: dict[str, dict]) -> list[dict]:
    """Canonicalize prior endpoints in memory for stable-ID migration matching."""
    result: list[dict] = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = deepcopy(raw)
        for side in ("from", "to"):
            endpoint, method, _candidates = _resolve_endpoint(row.get(side), components)
            if method in {"exact_id", "external_literal", "external_alias", "component_name"} and endpoint:
                row[side] = endpoint
        result.append(row)
    return result


def _write_diagnostics(output_dir: Path, rows: list[dict]) -> None:
    issues: list[dict] = []
    for row in rows:
        for detail in row.pop("_resolution_details", []) or []:
            if not isinstance(detail, dict):
                continue
            issues.append(
                {
                    "code": detail.get("code", "unresolved_endpoint"),
                    "boundary_id": row.get("id", "tb-0"),
                    "boundary_name": _clean_text(
                        row.get("name"),
                        fallback="Unnamed trust boundary",
                        limit=100,
                    ),
                    "side": detail.get("side", "both"),
                    "raw_value": _clean_text(detail.get("raw_value"), fallback="", limit=128),
                    "reason": _clean_text(
                        detail.get("reason"),
                        fallback="endpoint does not satisfy the canonical contract",
                        limit=240,
                    ),
                    "candidates": [
                        value
                        for value in detail.get("candidates", [])[:8]
                        if isinstance(value, str) and _COMPONENT_ID_RE.fullmatch(value)
                    ],
                }
            )
    issues.sort(key=lambda item: (_numeric_id(item["boundary_id"]), item["side"], item["code"]))
    result = {"schema_version": 1, "issues": issues}
    schema = json.loads(DIAGNOSTICS_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(result)
    atomic_write_json(output_dir / ".trust-boundary-diagnostics.json", result, sort_keys=False)


def _record_invalid_resolved_diagnostics(output_dir: Path, rows: list[dict]) -> None:
    """Merge consumer-side invariant failures into the normalized diagnostics."""
    path = output_dir / ".trust-boundary-diagnostics.json"
    current = _read_json(path, {}) or {}
    issues = [item for item in current.get("issues", []) if isinstance(item, dict)]
    existing = {(item.get("code"), item.get("boundary_id"), item.get("side")) for item in issues}
    for row in rows:
        key = ("invalid_resolved_endpoint", row.get("id"), "both")
        if key in existing:
            continue
        issues.append(
            {
                "code": "invalid_resolved_endpoint",
                "boundary_id": row["id"],
                "boundary_name": _clean_text(
                    row.get("name"),
                    fallback="Unnamed trust boundary",
                    limit=100,
                ),
                "side": "both",
                "raw_value": "",
                "reason": "resolved row failed dynamic component endpoint validation before dispatch",
                "candidates": [],
            }
        )
    result = {"schema_version": 1, "issues": issues}
    schema = json.loads(DIAGNOSTICS_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(result)
    atomic_write_json(path, result, sort_keys=False)


def _write_declaration_fingerprint(output_dir: Path, fingerprint: str | None) -> None:
    cache = output_dir / ".appsec-cache" / "baseline.json"
    state = _read_json(cache, {}) or {}
    if fingerprint is None:
        state.pop("trust_boundary_declaration_fingerprint", None)
    else:
        state["trust_boundary_declaration_fingerprint"] = fingerprint
    cache.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(cache, state)


def _glob_probe(glob: str) -> str:
    """Representative concrete path for a glob, so globs can be matched as paths."""
    return glob.replace("/**", "/_").replace("**", "_").replace("*", "_")


def _contained_in(inner: dict, outer: dict) -> bool:
    """True when every path of ``inner`` is already claimed by ``outer``."""
    inner_paths = [g.strip() for g in (inner.get("paths") or []) if isinstance(g, str) and g.strip()]
    outer_globs = [g.strip() for g in (outer.get("paths") or []) if isinstance(g, str) and g.strip()]
    if not inner_paths or not outer_globs:
        return False
    return all(any(_rc_glob_to_regex(g).search(_glob_probe(p)) for g in outer_globs) for p in inner_paths)


def _consolidate(rows: list[dict], components: dict[str, dict], warnings: list[str]) -> list[dict]:
    """Collapse over-modelled boundaries before IDs are assigned.

    A trust boundary earns its own row only when it asks its own question:
    *what must hold here, and does it?* Splitting one enforcement point per
    protocol or per role produces rows that are checked twice and clutter every
    downstream view, while the real difference — one channel across the boundary
    lacking a control — is a FINDING, not a second boundary.

    Three narrow rules, each requiring positive evidence of redundancy:

    1. Exact duplicates (same endpoints, kind AND name) are the same row emitted
       twice.
    2. A `privilege` crossing anchored at `external` that duplicates an existing
       crossing's endpoints is mis-anchored: privilege changes are enforced
       INSIDE the system (the model's own `backend-api -> backend-api` admin
       boundary is the precedent), and the perimeter it names is already covered
       by the row it duplicates. Its endpoints are moved inward rather than
       merged away, so the privilege question survives.
    3. Two internet-ingress crossings whose targets are the same code — one
       component's paths fully contained in the other's — share one perimeter:
       an embedded WebSocket gateway is reached through the same port and
       process as the API it lives in. The inner one folds into the outer.
    """
    out: list[dict] = []
    seen: dict[tuple, dict] = {}
    for row in rows:
        key = (row.get("from"), row.get("to"), row.get("kind"), (row.get("name") or "").strip().casefold())
        if key in seen:
            seen[key]["evidence"] = _merge_evidence(seen[key].get("evidence") or [], row.get("evidence") or [])
            warnings.append(f"consolidated duplicate boundary {row.get('name')!r}")
            continue
        seen[key] = row
        out.append(row)

    endpoint_pairs = Counter((r.get("from"), r.get("to")) for r in out)
    for row in out:
        target = row.get("to")
        if (
            row.get("kind") == "privilege"
            and row.get("from") == "external"
            and target in components
            and endpoint_pairs[(row.get("from"), target)] > 1
        ):
            warnings.append(
                f"re-anchored privilege boundary {row.get('name')!r} to {target} — "
                "a privilege change is enforced inside the system, and its perimeter "
                "is already modelled by another crossing with the same endpoints"
            )
            row["from"] = target

    ingress = [r for r in out if r.get("from") == "external" and r.get("to") in components]
    folded: list[dict] = []
    for index, row in enumerate(ingress):
        for other_index, other in enumerate(ingress):
            if other is row or other in folded or row.get("kind") != other.get("kind"):
                continue
            # Containment is symmetric when both rows enter the SAME component,
            # so "inner folds into outer" picks no side and the survivor would be
            # decided by list position alone. Keep the earlier row — the
            # first-wins rule every other merge here uses — so a later duplicate
            # cannot take over the identity, and with it the stable `tb-N`, of
            # the row that was already modelled.
            if row["to"] == other["to"] and other_index > index:
                continue
            if _contained_in(components[row["to"]], components[other["to"]]):
                other["evidence"] = _merge_evidence(other.get("evidence") or [], row.get("evidence") or [])
                # The folded-in component keeps a claim on the surviving row, so a
                # finding it owns can still reference the perimeter it sits behind.
                other["covers_components"] = sorted(
                    {
                        *(other.get("covers_components") or []),
                        *(row.get("covers_components") or []),
                        other["to"],
                        row["to"],
                    }
                )
                warnings.append(
                    f"folded ingress boundary {row.get('name')!r} into {other.get('name')!r} — "
                    f"{row['to']} is served by the same code as {other['to']}, so both name one perimeter"
                )
                folded.append(row)
                break
    return [r for r in out if r not in folded]


def normalize(
    *,
    repo_root: Path,
    sidecar: Path,
    prior_model: Path | None,
    output_dir: Path,
    raw_sidecar: dict | None = None,
    destination: Path | None = None,
) -> tuple[dict, list[str]]:
    repo_root, output_dir = repo_root.resolve(), output_dir.resolve()
    raw = raw_sidecar if raw_sidecar is not None else _read_json(sidecar, None)
    if not isinstance(raw, dict) or not isinstance(raw.get("trust_boundaries"), list):
        raise ValueError(f"sidecar is missing or malformed: {sidecar}")
    prior, prior_rows = _prior_boundaries(prior_model)
    components_data = _read_json(output_dir / ".components.json", {})
    component_rows = _component_rows(components_data, prior)
    components = {row["id"]: row for row in component_rows}
    prior_rows = _canonicalize_prior_rows(prior_rows, components)
    warnings: list[str] = []
    legacy = raw.get("schema_version") != 2
    detected = [
        row
        for item in raw["trust_boundaries"]
        if (
            row := _normalize_row(
                item,
                repo_root=repo_root,
                components=components,
                legacy_input=legacy,
                warnings=warnings,
                source="detected",
            )
        )
    ]
    declarations, fingerprint = _load_declarations(repo_root, components, warnings)
    merged = _merge_declarations(detected, declarations, prior_rows, warnings)
    # After declaration merging, which is the last thing that can change `kind`.
    _apply_axes(merged)
    # Before IDs exist, so consolidating costs no ID churn downstream.
    merged = _consolidate(merged, components, warnings)
    _assign_ids(merged, prior_rows, output_dir, warnings)
    if len({row["id"] for row in merged}) != len(merged):
        raise ValueError("normalization produced duplicate trust-boundary IDs")
    merged.sort(key=lambda row: _numeric_id(row["id"]))
    _write_diagnostics(output_dir, merged)
    result = {"schema_version": 2, "trust_boundaries": merged}
    schema = json.loads(NORMALIZED_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(result)
    atomic_write_json(destination or sidecar, result, sort_keys=False)
    _write_declaration_fingerprint(output_dir, fingerprint)
    return result, warnings


def _component_map(output_dir: Path) -> dict[str, dict]:
    data = _read_json(output_dir / ".components.json", {}) or {}
    return {
        row["id"]: row for row in data.get("components", []) if isinstance(row, dict) and isinstance(row.get("id"), str)
    }


def _prior_boundary_refs(output_dir: Path) -> set[tuple[str, str]]:
    model = _read_yaml(output_dir / "threat-model.yaml", {}) or {}
    result: set[tuple[str, str]] = set()
    for finding in model.get("threats", []) if isinstance(model, dict) else []:
        if not isinstance(finding, dict):
            continue
        for ref in finding.get("boundary_refs", []) or []:
            if isinstance(ref, dict) and ref.get("boundary_id") and ref.get("origin_component_id"):
                result.add((ref["boundary_id"], ref["origin_component_id"]))
    return result


def _path_specificity(component: dict, file_path: str) -> int | None:
    """Highest specificity among the component globs claiming ``file_path``."""
    best: int | None = None
    for glob in component.get("paths") or []:
        if not isinstance(glob, str) or not glob.strip():
            continue
        glob = glob.strip()
        if _rc_glob_to_regex(glob).search(file_path):
            score = _rc_glob_specificity(glob)
            best = score if best is None else max(best, score)
    return best


def _evidence_owners(boundary: dict, components: dict[str, dict], endpoint_ids: set[str]) -> set[str]:
    """Components claiming a boundary's evidence more precisely than its endpoints.

    Endpoint adjacency alone cannot name the component that *implements* a
    crossing whose far side is ``external``. tb-5 ``backend-api -> external``
    is the LLM egress, yet ``llm-integration`` is never an endpoint and was
    therefore never offered the one boundary it owns — juice-shop 2026-07-27
    shipped that boundary with zero linked findings for exactly this reason.
    Ownership of the cited evidence file is the missing signal.

    Two guards keep this from inventing adjacency:

    * The endpoint must claim the evidence too. When it does not, the declared
      topology and the cited evidence disagree — a data-quality problem this
      function must surface rather than paper over by handing the boundary to
      whichever component happens to own the file.
    * The claim must be STRICTLY more specific. A file both sides claim equally
      well says nothing about ownership: ``server.ts`` sits in both
      ``backend-api`` and ``socket-io-realtime`` globs, and a loose match would
      hand the "Admin Zone" boundary to the WebSocket gateway.

    What remains is the narrow, intended case: the endpoint is the coarse owner
    (``routes/**``) and a finer-grained component claims the exact file
    (``routes/chat.ts``), so the latter is the component that implements it.
    """
    owners: set[str] = set()
    resolvable_endpoints = endpoint_ids & set(components)
    for entry in boundary.get("evidence") or []:
        if not isinstance(entry, dict):
            continue
        file_path = str(entry.get("file") or "").strip()
        if not file_path:
            continue
        endpoint_scores = [
            score
            for cid in resolvable_endpoints
            if (score := _path_specificity(components[cid], file_path)) is not None
        ]
        baseline = max(endpoint_scores, default=None)
        for cid, component in components.items():
            if cid in endpoint_ids:
                continue
            score = _path_specificity(component, file_path)
            if baseline is not None and score is not None and score > baseline:
                owners.add(cid)
    return owners


def _glob_probe(glob: str) -> str:
    """Representative concrete path for a component glob, for containment tests."""
    return glob.replace("/**", "/_").replace("**", "_").replace("*", "_")


def _containing_component_id(cid: str, components: dict[str, dict]) -> str | None:
    """The coarse component whose globs already claim every path of ``cid``.

    Role-folded components (an `auth` surface carved out of `backend-api`) are
    reconciled into the dispatch set after Phase 3, so no boundary names them as
    an endpoint and they start with no candidates at all — juice-shop
    2026-07-27 ran `auth` and `web3-nft`, 17 findings between them, with zero
    boundary context. Their parent's candidates are the closest correct answer.
    """
    own = [g.strip() for g in (components.get(cid, {}).get("paths") or []) if isinstance(g, str) and g.strip()]
    if not own:
        return None
    parents: list[tuple[int, str]] = []
    for pid, parent in components.items():
        if pid == cid:
            continue
        globs = [g.strip() for g in (parent.get("paths") or []) if isinstance(g, str) and g.strip()]
        if not globs:
            continue
        if all(any(_rc_glob_to_regex(g).search(_glob_probe(p)) for g in globs) for p in own):
            parents.append((max(_rc_glob_specificity(g) for g in globs), pid))
    if not parents:
        return None
    # Most specific containing component wins; id breaks ties deterministically.
    return min(parents, key=lambda item: (-item[0], item[1]))[1]


def _transitions(boundary: dict) -> set[str]:
    """The trust-change axis, tolerating rows that predate the derivation."""
    stored = boundary.get("transition")
    if isinstance(stored, list):
        return {item for item in stored if item in TRANSITIONS}
    return set(_axes_for_kind(boundary.get("kind"))[1])


def _surface(boundary: dict) -> str:
    stored = boundary.get("surface")
    return stored if stored in SURFACES else _axes_for_kind(boundary.get("kind"))[0]


def _focus(boundary: dict, component: dict, prior_refs: set[tuple[str, str]]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    cid = component.get("id")
    if boundary.get("confidence") == "unknown" or boundary.get("assumption") == NEUTRAL_LEGACY_ASSUMPTION:
        return "catalog-only", ["unknown legacy assumption or confidence"]
    if (boundary["id"], cid) in prior_refs:
        reasons.append("prior verified boundary reference")
    if boundary.get("from") == "external":
        reasons.append("explicit external entry")
    transitions = _transitions(boundary)
    principal = sorted(transitions & {"identity", "privilege", "tenant"})
    if principal:
        reasons.append(f"{'/'.join(principal)} transition")
    if "operator" in transitions:
        reasons.append(f"operator crossing ({_surface(boundary)})")
    if reasons:
        return "primary", reasons
    if "data-origin" in transitions:
        reasons.append("data-origin transition")
    if component.get("handles_sensitive_data"):
        reasons.append("crossing into sensitive-data component")
    if reasons:
        return "secondary", reasons
    return "catalog-only", ["ordinary crossing without prioritized trust-change signal"]


@lru_cache(maxsize=1)
def _selection_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(SELECTION_SCHEMA.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def validate_trust_boundary_selection(
    audit: Any,
    *,
    known_component_ids: set[str] | None = None,
) -> None:
    """Validate the selection sidecar and inherited-component references."""
    _selection_validator().validate(audit)
    components = audit["components"]
    for component_id, entry in components.items():
        parent_id = entry.get("inherited_from")
        if not parent_id:
            continue
        if parent_id == component_id:
            raise jsonschema.ValidationError(
                f"components.{component_id}.inherited_from must not reference the component itself"
            )
        if known_component_ids is not None and parent_id not in known_component_ids:
            raise jsonschema.ValidationError(
                f"components.{component_id}.inherited_from references unknown component {parent_id!r}"
            )
        if parent_id not in components:
            raise jsonschema.ValidationError(
                f"components.{component_id}.inherited_from references component {parent_id!r} without a selection audit"
            )


def prepare_contexts(
    *,
    repo_root: Path,
    output_dir: Path,
    component_ids: Iterable[str],
    depth: str,
) -> dict:
    from resolve_config import BOUNDARY_CANDIDATE_LIMITS

    if depth not in BOUNDARY_CANDIDATE_LIMITS:
        raise ValueError(f"unknown assessment depth: {depth}")
    sidecar = _read_json(output_dir / ".trust-boundaries.json", {}) or {}
    components = _component_map(output_dir)
    component_id_set = set(components)
    boundaries = [row for row in sidecar.get("trust_boundaries", []) if isinstance(row, dict)]
    invalid_resolved = [
        row
        for row in boundaries
        if row.get("resolution_status") == "resolved" and not boundary_endpoints_valid(row, component_id_set)
    ]
    # Fail open for the assessment but fail closed for boundary semantics. The
    # strict schema correctly rejects prose endpoints on resolved rows; context
    # preparation still needs to surface/defer such a persisted artifact rather
    # than abort before the diagnostics path can run.
    validation_doc = deepcopy(sidecar)
    invalid_ids = {row.get("id") for row in invalid_resolved}
    for row in validation_doc.get("trust_boundaries", []) if isinstance(validation_doc, dict) else []:
        if isinstance(row, dict) and row.get("id") in invalid_ids:
            row["resolution_status"] = "unresolved"
    schema = json.loads(NORMALIZED_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(validation_doc)
    if invalid_resolved:
        _record_invalid_resolved_diagnostics(output_dir, invalid_resolved)
        for row in invalid_resolved:
            print(
                f"TRUST_BOUNDARY_WARN: {row.get('id')}: invalid resolved endpoints "
                f"from={row.get('from')!r} to={row.get('to')!r}",
                file=sys.stderr,
            )
    prior_refs = _prior_boundary_refs(output_dir)
    # Precomputed once per boundary: endpoint adjacency cannot name the
    # component implementing an `-> external` crossing (see _evidence_owners).
    evidence_owners = {
        boundary["id"]: _evidence_owners(
            boundary,
            components,
            {boundary.get("from"), boundary.get("to")} & component_id_set,
        )
        for boundary in boundaries
        if boundary.get("id")
    }
    selected_component_ids = list(dict.fromkeys(str(x) for x in component_ids if x))
    context_root = output_dir / ".dispatch-context"
    context_root.mkdir(parents=True, exist_ok=True)
    audit: dict[str, Any] = {
        "schema_version": 1,
        "depth": depth,
        "max_candidates_per_component": BOUNDARY_CANDIDATE_LIMITS[depth],
        "components": {},
    }
    # Selection is decided across all components at once (inheritance and the
    # coverage guarantee below both need the global picture), so collect first
    # and write the context files only once every list is final.
    state: dict[str, dict[str, Any]] = {}
    for cid in selected_component_ids:
        context_path = context_root / cid / "trust-boundaries.json"
        try:
            context_path.unlink()
        except FileNotFoundError:
            pass
        component = components.get(cid)
        if component is None:
            audit["components"][cid] = {
                "eligible_ids": [],
                "selected_ids": [],
                "omitted_ids": [],
                "deferred_ids": [],
                "invalid_ids": [row["id"] for row in invalid_resolved],
                "reason": "selected STRIDE component absent from reconciled inventory",
            }
            continue
        candidates: list[tuple[tuple, dict, str, list[str]]] = []
        deferred: list[str] = []
        invalid: list[str] = []
        for boundary in boundaries:
            if boundary.get("resolution_status") != "resolved":
                deferred.append(boundary["id"])
                continue
            if not boundary_endpoints_valid(boundary, component_id_set):
                deferred.append(boundary["id"])
                invalid.append(boundary["id"])
                continue
            is_endpoint = cid in {boundary.get("from"), boundary.get("to"), *(boundary.get("covers_components") or [])}
            owns_evidence = cid in evidence_owners.get(boundary["id"], set())
            if not is_endpoint and not owns_evidence:
                continue
            focus, reasons = _focus(boundary, component, prior_refs)
            if focus == "catalog-only" or (depth == "quick" and focus != "primary"):
                deferred.append(boundary["id"])
                continue
            if owns_evidence and not is_endpoint:
                reasons = [*reasons, "implements the crossing (owns cited evidence)"]
            transitions = _transitions(boundary)
            rank = (
                0 if (boundary["id"], cid) in prior_refs else 1,
                0 if boundary.get("from") == "external" else 1,
                0 if transitions & {"identity", "privilege", "tenant"} else 1,
                0 if "data-origin" in transitions and component.get("handles_sensitive_data") else 1,
                0 if "operator" in transitions else 1,
                {"confirmed": 0, "inferred": 1, "unknown": 2}.get(boundary.get("confidence"), 2),
                _numeric_id(boundary["id"]),
            )
            candidates.append((rank, boundary, focus, reasons))
        candidates.sort(key=lambda item: item[0])
        state[cid] = {"candidates": candidates, "deferred": deferred, "invalid": invalid, "inherited_from": None}

    # A component with no candidates of its own inherits its parent's. Applied
    # ONLY when the list is empty: giving every folded sub-component the
    # parent's boundaries would crowd each one's own crossing out of the cap.
    for cid, entry in state.items():
        if entry["candidates"]:
            continue
        parent_id = _containing_component_id(cid, components)
        parent = state.get(parent_id) if parent_id else None
        if not parent or not parent["candidates"]:
            continue
        entry["candidates"] = [
            (rank, boundary, focus, [*reasons, f"inherited from containing component {parent_id}"])
            for rank, boundary, focus, reasons in parent["candidates"]
        ]
        entry["inherited_from"] = parent_id

    limit = BOUNDARY_CANDIDATE_LIMITS[depth]
    for entry in state.values():
        entry["chosen"], entry["omitted"] = entry["candidates"][:limit], entry["candidates"][limit:]

    # Coverage redistribution. The cap is per component, so a boundary ranked
    # just below it reaches no analyzer at all and can never acquire a finding —
    # juice-shop 2026-07-27 lost tb-5 (the LLM egress) this way, at rank 5 of 4
    # on its only eligible component.
    #
    # The fix must not simply append past the cap: with more boundaries than
    # capacity that degenerates into no cap at all. Instead swap, and only
    # against a boundary some OTHER component already covers. Each component
    # keeps exactly `limit` rows, and the trade is strictly positive — the
    # displaced crossing is still analyzed elsewhere, the uncovered one stops
    # being invisible. When nothing is displaceable the gap is real and gets
    # reported below rather than papered over.
    def _covered_elsewhere(bid: str, owner: str) -> bool:
        return any(item[1]["id"] == bid for cid, entry in state.items() if cid != owner for item in entry["chosen"])

    covered = {boundary["id"] for entry in state.values() for _r, boundary, _f, _rs in entry["chosen"]}
    redistributed: dict[str, str] = {}
    for boundary in boundaries:
        bid = boundary.get("id")
        if boundary.get("resolution_status") != "resolved" or bid in covered:
            continue
        best: tuple[str, tuple] | None = None
        for cid, entry in state.items():
            for item in entry["omitted"]:
                if item[1]["id"] == bid and (best is None or item[0] < best[1][0]):
                    best = (cid, item)
        if best is None:
            continue
        cid, item = best
        displaceable = [c for c in state[cid]["chosen"] if _covered_elsewhere(c[1]["id"], cid)]
        if not displaceable:
            continue
        victim = max(displaceable, key=lambda c: c[0])
        state[cid]["chosen"] = [c for c in state[cid]["chosen"] if c[1]["id"] != victim[1]["id"]] + [item]
        state[cid]["omitted"] = [o for o in state[cid]["omitted"] if o[1]["id"] != bid] + [victim]
        redistributed[bid] = cid
        covered.add(bid)

    def _context_row(boundary: dict, focus: str, reasons: list[str]) -> dict:
        # The legs decide the analyzer's `boundary_refs[].leg`, whose schema enum
        # is closed. Left out of the dispatch context the analyzer has only the
        # boundary NAME to work from and composes a label the gate rejects, which
        # re-dispatches the whole component (juice-shop 2026-08-02: "Sequelize
        # model parameter binding" became "parameterized binding" while tb-3
        # declared `data-interpretation`). Project the synthesized list rather
        # than the raw field so a row no analyst annotated still carries the
        # vocabulary its direction implies.
        row = {
            key: deepcopy(boundary[key])
            for key in ("id", "name", "from", "to", "kind", "assumption", "evidence", "confidence")
            if key in boundary
        }
        legs = boundary_legs(boundary)
        if legs:
            row["assumption_legs"] = deepcopy(legs)
        return row | {"focus": focus, "focus_reasons": reasons}

    for cid, entry in state.items():
        context_rows = [_context_row(boundary, focus, reasons) for _rank, boundary, focus, reasons in entry["chosen"]]
        if context_rows:
            component_dir = context_root / cid
            component_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                context_root / cid / "trust-boundaries.json",
                {"schema_version": 1, "adjacent_trust_boundaries": context_rows},
                sort_keys=False,
            )
        audit["components"][cid] = {
            "eligible_ids": [item[1]["id"] for item in entry["candidates"]],
            "selected_ids": [item[1]["id"] for item in entry["chosen"]],
            "omitted_ids": [item[1]["id"] for item in entry["omitted"]],
            "deferred_ids": sorted(set(entry["deferred"]), key=_numeric_id),
            "invalid_ids": sorted(set(entry["invalid"]), key=_numeric_id),
            "focus_reasons": {item[1]["id"]: item[3] for item in entry["candidates"]},
        }
        if entry["inherited_from"]:
            audit["components"][cid]["inherited_from"] = entry["inherited_from"]

    # Coverage is only derivable by cross-referencing every component, so state
    # it once. An uncovered resolved boundary reaches no analyzer and can never
    # acquire a finding — that is a reportable gap, not a quiet omission.
    resolved_ids = [b["id"] for b in boundaries if b.get("resolution_status") == "resolved"]
    uncovered = [bid for bid in resolved_ids if bid not in covered]
    audit["coverage"] = {
        "resolved_ids": sorted(resolved_ids, key=_numeric_id),
        "covered_ids": sorted(covered, key=_numeric_id),
        "uncovered_ids": sorted(uncovered, key=_numeric_id),
        "redistributed": redistributed,
    }
    for bid, cid in redistributed.items():
        print(
            f"TRUST_BOUNDARY_WARN: {bid}: swapped into {cid} to keep it covered — "
            "it fell below the per-component cap everywhere",
            file=sys.stderr,
        )
    for bid in uncovered:
        print(
            f"TRUST_BOUNDARY_WARN: {bid}: resolved boundary reached no STRIDE component — "
            "it can acquire no findings this run",
            file=sys.stderr,
        )
    validate_trust_boundary_selection(audit, known_component_ids=component_id_set)
    atomic_write_json(context_root / "trust-boundary-selection.json", audit, sort_keys=False)
    return audit


def validate_finding_boundary_refs(
    finding: dict,
    *,
    boundaries: Iterable[dict],
    origin_component_id: str | None,
    candidate_ids: set[str] | None,
    require_candidate: bool,
    known_component_ids: set[str] | None = None,
) -> tuple[list[dict], list[str]]:
    """Fail-open validation for optional finding traceability.

    Invalid references are removed while the security finding is retained.
    ``candidate_ids`` is required only at the fresh analyzer→merge boundary;
    carried findings are checked against canonical existence, adjacency and
    surviving evidence instead.
    """
    boundary_by_id = {
        row.get("id"): row for row in boundaries if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    evidence: set[tuple[str, int | None]] = set()
    primary = finding.get("evidence")
    primary_rows = primary if isinstance(primary, list) else [primary]
    for item in [*primary_rows, *(finding.get("instances") or [])]:
        if isinstance(item, dict) and item.get("file"):
            evidence.add((str(item["file"]), item.get("line")))
    cleaned: list[dict] = []
    diagnostics: list[str] = []
    seen: set[tuple[str, str]] = set()
    for ref in finding.get("boundary_refs") or []:
        if not isinstance(ref, dict):
            diagnostics.append("removed malformed boundary reference")
            continue
        boundary_id = ref.get("boundary_id")
        origin = ref.get("origin_component_id")
        key = (str(boundary_id or ""), str(origin or ""))
        boundary = boundary_by_id.get(boundary_id)
        reason: str | None = None
        if key in seen:
            reason = f"removed duplicate reference {boundary_id!r}"
        elif boundary is None:
            reason = f"removed unknown boundary reference {boundary_id!r}"
        elif boundary.get("resolution_status") != "resolved" or boundary.get("confidence") != "confirmed":
            reason = f"removed non-confirmed/non-resolved boundary reference {boundary_id!r}"
        elif (
            not boundary_endpoints_valid(boundary, known_component_ids)
            if known_component_ids is not None
            else not _boundary_endpoint_shape_valid(boundary)
        ):
            reason = f"removed invalid-canonical-endpoint boundary reference {boundary_id!r}"
        elif origin_component_id is not None and origin != origin_component_id:
            reason = f"removed wrong-origin boundary reference {boundary_id!r}"
        elif not isinstance(origin, str) or origin not in {
            boundary.get("from"),
            boundary.get("to"),
            *(boundary.get("covers_components") or []),
        }:
            reason = f"removed non-adjacent boundary reference {boundary_id!r}"
        elif require_candidate and (candidate_ids is None or boundary_id not in candidate_ids):
            reason = f"removed current-run non-candidate boundary reference {boundary_id!r}"
        elif not isinstance(ref.get("rationale"), str) or not 20 <= len(ref["rationale"].strip()) <= 240:
            reason = f"removed invalid-rationale boundary reference {boundary_id!r}"
        locations = ref.get("evidence_locations")
        if reason is None and (
            not isinstance(locations, list)
            or not locations
            or len(locations) > 3
            or any(
                not isinstance(location, dict) or (location.get("file"), location.get("line")) not in evidence
                for location in locations
            )
        ):
            reason = f"removed evidence-free/non-owned boundary reference {boundary_id!r}"
        if reason:
            diagnostics.append(reason)
            continue
        seen.add(key)
        kept = deepcopy(ref)
        # `leg` says WHICH condition of the crossing this finding breaks. It is
        # optional and fail-open on its own: the ref already carries a rationale
        # and finding-owned evidence, so an unusable leg name costs the leg, not
        # the link — dropping a validated link over a label would lose the very
        # traceability this function exists to keep. Without it the leg view
        # falls back to the CWE map.
        leg = str(kept.get("leg") or "").strip().casefold()
        if leg and leg not in {entry["leg"] for entry in boundary_legs(boundary)}:
            diagnostics.append(f"removed invalid leg {leg!r} from boundary reference {boundary_id!r}")
            leg = ""
        if leg:
            kept["leg"] = leg
        else:
            kept.pop("leg", None)
        cleaned.append(kept)
        if len(cleaned) == 2:
            break
    return cleaned, diagnostics


# --------------------------------------------------------------------------- #
# Deterministic consolidation (juice-shop 2026-07-30)
#
# `agents/appsec-trust-boundary-analyst.md` already defines a boundary as ONE
# enforcement point and tells the analyst to "consolidate protocols or roles that
# name one enforcement point" — but nothing downstream checked it, so every
# candidate became a `tb-N` 1:1. A juice-shop run turned 19 signals into 6
# boundaries with all 19 dispositions set to `boundary`; `same-trust` was never
# used once. Two of the six were modelling errors: an in-process app→DB pair
# presented as a privilege transition, and a Prometheus scrape modelled as
# egress.
# --------------------------------------------------------------------------- #
_ROUTE_REGISTRATION_RE = re.compile(
    r"\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|head|options|all|use)\s*\(",
)


def _glob_matcher(pattern: str) -> re.Pattern[str]:
    """Compile a path glob so `**` spans separators and `*` does not."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _paths_contained(inner: list[str], outer: list[str]) -> bool:
    """True when every glob in ``inner`` is covered by some glob in ``outer``.

    Containment — not zone equality — is the reliable same-deployable signal.
    juice-shop zones `sqlite-database` as `peer-service` while the boundary's own
    assumption says "there is no separate network hop", so a zone comparison
    would have missed it; `models/**` and `data/sequelize.ts` sitting inside
    `models/**` + `data/**` would not.
    """
    if not inner or not outer:
        return False
    matchers = [_glob_matcher(p) for p in outer if isinstance(p, str) and p]
    if not matchers:
        return False
    return all(
        isinstance(candidate, str) and candidate and any(m.match(candidate) for m in matchers) for candidate in inner
    )


def _same_deployable(a_paths: list[str], b_paths: list[str]) -> bool:
    return _paths_contained(a_paths, b_paths) or _paths_contained(b_paths, a_paths)


def _deployable_root(component_id: Any, components: dict[str, dict]) -> Any:
    """The outermost component whose paths contain ``component_id``'s.

    Same primitive as `_same_deployable`, walked transitively: `auth-service`
    (`routes/login.ts`, `lib/insecurity.ts`) sits inside `backend-api`
    (`routes/**`, `lib/**`), so both name one process and one perimeter.

    Deliberately NOT derived from `deployment_zones` (see `_paths_contained`) and
    not from Dockerfile/compose: neither exists as structured per-component data,
    and a compose file describes a deployment variant rather than the tree under
    assessment. A component that is contained by nobody is its own deployable.
    """
    if component_id not in components:
        return component_id
    current = component_id
    for _ in range(len(components)):
        own = [p for p in (components[current].get("paths") or []) if isinstance(p, str) and p]
        if not own:
            return current
        outer = [
            cid
            for cid, row in components.items()
            if cid != current
            and _paths_contained(own, [p for p in (row.get("paths") or []) if isinstance(p, str) and p])
            # Mutual containment is not nesting; leaving it to the id tie-break
            # below would make the root depend on iteration order.
            and not _paths_contained([p for p in (row.get("paths") or []) if isinstance(p, str) and p], own)
        ]
        if not outer:
            return current
        current = sorted(outer)[0]
    return current


def _evidence_line(repo_root: Path, entry: dict) -> str:
    """The single source line an evidence entry points at ("" when unreadable)."""
    file_name = entry.get("file")
    line_no = entry.get("line")
    if not isinstance(file_name, str) or not isinstance(line_no, int) or line_no < 1:
        return ""
    target = (repo_root / file_name).resolve()
    try:
        target.relative_to(repo_root.resolve())
    except ValueError:
        return ""
    try:
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            for index, text in enumerate(handle, start=1):
                if index == line_no:
                    return text
                if index > line_no:
                    break
    except OSError:
        return ""
    return ""


_CONFIDENCE_RANK = {"unknown": 0, "inferred": 1, "confirmed": 2}

# The component contract already states where a component's code runs, so this is
# read, never inferred. Both `schemas/fragments/components.schema.json` and
# `schemas/trust-boundary-assessment-input.schema.json` fix the vocabulary to
# exactly `client` / `application` / `data`, and only `client` denotes code that
# executes on the user's device — browser SPA, mobile app, desktop client.
# A missing tier, or any value outside the enum, is treated as server-side:
# folding or dropping a boundary that is actually real is the dangerous
# direction, so absence must never read as "client".
_CLIENT_TIERS = {"client"}


def _is_client_tier(component_id: Any, components: dict[str, dict]) -> bool:
    """True only when the component registry positively declares client tier."""
    component = components.get(component_id) if isinstance(component_id, str) else None
    tier = component.get("tier") if isinstance(component, dict) else None
    return isinstance(tier, str) and tier.strip().casefold() in _CLIENT_TIERS


def _retarget_name(name: Any, old_endpoint: str, new_endpoint: str) -> Any:
    """Rewrite the ``<crossing>: <point>`` prefix so the name cannot lie."""
    if not isinstance(name, str):
        return name
    for arrow in ("→", "->"):
        prefix = f"{old_endpoint} {arrow}"
        if name.casefold().startswith(prefix.casefold()):
            return f"{new_endpoint} {arrow}" + name[len(prefix) :]
    return name


def _grouping_endpoint(candidate: dict, crossing_class: str, components: dict[str, dict]) -> Any:
    """The inner endpoint a crossing is grouped by (deployable for ingress)."""
    target = candidate.get("to")
    return _deployable_root(target, components) if crossing_class == "ingress" else target


def _crossing_class(candidate: dict) -> str:
    if candidate.get("from") == "external":
        return "ingress"
    if candidate.get("to") == "external":
        return "egress"
    return "internal"


def _consolidate_candidates(
    candidates: list[dict],
    *,
    components: dict[str, dict],
    repo_root: Path,
    dropped: dict[str, str] | None = None,
) -> tuple[list[dict], dict[str, str], list[str]]:
    """Normalize and merge candidates before they become canonical boundaries.

    Four deterministic passes, all conservative:

    1. **Direction** — a candidate modelled ``X → external`` whose own evidence
       lands on a route registration is an ingress crossing; flip it.
    2. **Client tier** — code the component registry declares ``tier: client``
       executes on the user's device, next to the attacker, so it is not a trust
       zone. A crossing OUT of it really starts at ``external`` and is rewritten
       there (the absorbed component is recorded in ``covers_components`` so the
       findings anchored to it keep an adjacent boundary); a crossing INTO it
       protects nothing and is removed — reported through ``dropped``, never
       silently. Both rules require a positive ``tier: client``; a missing or
       unknown tier is left alone.
    3. **Same deployable** — endpoints that ship in one process are an internal
       enforcement interface, so force ``kind: process``. They are NOT discarded:
       the injection / mass-assignment / encryption-at-rest findings anchor here,
       and dropping the row to `same-trust` would leave them nowhere to attach.
       `same-trust` stays reserved for signals with no interface behind them.
    4. **Merge** — candidates sharing one `enforcement_point` within the same
       crossing class are one boundary; those naming none fall back to the
       crossing itself, with ingress compared per deployable rather than per
       component label. A merge spanning components records them in
       `covers_components` so nothing loses its anchor. Over-merging destroys
       information silently, whereas under-merging stays visible in the
       catalogue and is fixable next run — so every widening here is bounded by
       evidence (path containment) and by `kind`.

    Returns ``(surviving_candidates, alias_map, notes)``; ``alias_map`` maps every
    original ``candidate_key`` to its survivor so signal promotion still resolves.
    ``dropped`` is filled with ``candidate_key -> reason`` for every candidate
    pass 2 removed, following this module's out-parameter convention for
    diagnostics (`_consolidate`, `_normalize_row`).
    """
    notes: list[str] = []
    if dropped is None:
        dropped = {}
    working = [deepcopy(row) for row in candidates]

    for candidate in working:
        key = candidate["candidate_key"]
        authored_point = candidate.get("enforcement_point")
        cleaned_point = _clean_enforcement_point(authored_point)
        if cleaned_point is None and isinstance(authored_point, str) and authored_point.strip():
            notes.append(
                f"{key}: discarded generic enforcement point {authored_point.strip()!r} — "
                "it names no specific control, so the crossing decides the grouping"
            )
        if cleaned_point is None:
            candidate.pop("enforcement_point", None)
        else:
            candidate["enforcement_point"] = cleaned_point
        if candidate.get("to") == "external" and candidate.get("from") in components:
            if _looks_inbound(repo_root, candidate):
                candidate["from"], candidate["to"] = "external", candidate["from"]
                notes.append(
                    f"{key}: direction corrected to ingress — evidence is a route registration, not an outbound call"
                )
        # Client-side code is not a trust zone. It is delivered to the user's
        # device and executes there, on the attacker's side of every control the
        # server has: the server cannot tell a request from its own SPA apart
        # from a forged one, and nothing the SPA "enforces" survives a modified
        # client. Run after the direction correction so a mis-modelled
        # `client → external` that is really inbound is judged in its corrected
        # form, and before the same-deployable rule, which must not claim that a
        # browser shares a process with the server that ships it.
        source, target = candidate.get("from"), candidate.get("to")
        if target in components and _is_client_tier(target, components):
            point = candidate.get("enforcement_point")
            if point:
                # Fail safe. A named, specific control on the way into the client
                # is either a real control this model would lose (a token or
                # cookie issued at that step) or evidence that the component is
                # not purely browser-resident after all — server-rendered, or a
                # BFF that merely got tagged `client`. Deleting an evidenced
                # control is the dangerous direction, so keep the row and say why.
                notes.append(
                    f"{key}: kept {source} -> {target} into client-tier {target} — it names the "
                    f"enforcement point {point!r}, which the model would lose with the row; a "
                    f"declared control means a real check, or a component that is not purely client-side"
                )
            else:
                dropped[key] = (
                    f"{target} is a client-tier component: it executes on the user's device, so it is "
                    f"not a trust zone. The crossing {source} -> {target} names no enforcement point "
                    f"and therefore makes no security decision."
                )
                notes.append(f"{key}: dropped {source} -> {target} — {dropped[key]}")
                continue
        elif source in components and target in components and source != target and _is_client_tier(source, components):
            # The real origin is `external`; the client component is only where
            # the request was composed. Recorded in `covers_components` so the
            # findings that live in that code keep an adjacent boundary
            # (`_boundary_adjacency.is_adjacent`), then handed to the ordinary
            # merge below — an identical crossing already modelled from
            # `external` absorbs it, a genuinely different one keeps its row.
            candidate["from"] = "external"
            candidate["name"] = _retarget_name(candidate.get("name"), source, "external")
            candidate["covers_components"] = sorted({source, target, *(candidate.get("covers_components") or [])})
            notes.append(
                f"{key}: source {source} -> external — {source} is client-tier, so it runs on the "
                f"user's device on the untrusted side of {target}; the crossing it describes is the "
                f"one the outside world already makes"
            )
        if (
            candidate.get("from") == "external"
            and candidate.get("confidence") == "inferred"
            and _ingress_is_evidenced(repo_root, candidate)
        ):
            candidate["confidence"] = "confirmed"
            # Stamped so a reader (and a later run) can tell a deterministic
            # upgrade from an analyst's own source inspection — the catalogue
            # shows the same word for both.
            candidate["confidence_basis"] = "route-evidence"
            notes.append(f"{key}: confidence inferred -> confirmed — cited evidence line registers an inbound route")
        source, target = candidate.get("from"), candidate.get("to")
        if source in components and target in components:
            if (
                _same_deployable(
                    components[source].get("paths") or [],
                    components[target].get("paths") or [],
                )
                and candidate.get("kind") != "process"
            ):
                notes.append(
                    f"{key}: reclassified {candidate.get('kind')!r} -> 'process' — "
                    f"{source} and {target} ship in one deployable"
                )
                candidate["kind"] = "process"

    working = [candidate for candidate in working if candidate["candidate_key"] not in dropped]

    # Separation must be justified, not consolidation. A declared
    # `enforcement_point` IS the justification: candidates that name one group by
    # it, so two distinct controls at the same endpoints stay apart. Candidates
    # that name none fall back to grouping by the crossing itself — same
    # endpoints, same direction, no stated reason to be told apart, one boundary.
    # The two schemes never mix: a declared point is a claim to separateness and
    # is not absorbed by an undeclared neighbour.
    #
    # The fallback compares the crossing, not the component label. Components are
    # a logical model: juice-shop splits one Express process into `backend-api`,
    # `auth-service`, `chat-service` and `realtime-channel`, so `external ->
    # backend-api` and `external -> auth-service` are one perimeter — one port,
    # one process, one enforcement surface — that a literal endpoint comparison
    # keeps apart, which is exactly the fragmentation this pass exists to undo.
    # Two narrow guards keep the widening honest:
    #   * only INGRESS widens. On egress the far side is a specific third party
    #     (`chat-service -> external` is an LLM API, `backend-api -> external` a
    #     metrics collector); collapsing those by deployable would merge two
    #     unrelated dependencies into one row.
    #   * `kind` joins the key. Crossings into one process still differ in what
    #     they enforce — an OAuth assertion is not the generic HTTPS perimeter —
    #     and without it the widening would swallow that distinction.
    groups: dict[tuple, list[dict]] = {}
    for candidate in working:
        point = candidate.get("enforcement_point")
        crossing_class = _crossing_class(candidate)
        if isinstance(point, str) and point.strip():
            key = ("point", point.casefold(), crossing_class)
        else:
            key = (
                "crossing",
                candidate.get("from"),
                _grouping_endpoint(candidate, crossing_class, components),
                crossing_class,
                candidate.get("kind"),
            )
        groups.setdefault(key, []).append(candidate)

    singles: list[dict] = []
    merged: list[dict] = []
    alias: dict[str, str] = {}
    for members in groups.values():
        survivor = members[0]
        alias[survivor["candidate_key"]] = survivor["candidate_key"]
        for other in members[1:]:
            alias[other["candidate_key"]] = survivor["candidate_key"]
            for field in ("covered_signal_ids", "covered_flow_ids"):
                combined = list(survivor.get(field) or []) + list(other.get(field) or [])
                survivor[field] = sorted(dict.fromkeys(combined))
            seen_evidence = {
                (e.get("file"), e.get("line")) for e in survivor.get("evidence") or [] if isinstance(e, dict)
            }
            for entry in other.get("evidence") or []:
                marker = (entry.get("file"), entry.get("line")) if isinstance(entry, dict) else None
                if marker and marker not in seen_evidence:
                    seen_evidence.add(marker)
                    survivor.setdefault("evidence", []).append(deepcopy(entry))
            if _CONFIDENCE_RANK.get(other.get("confidence"), 0) > _CONFIDENCE_RANK.get(survivor.get("confidence"), 0):
                survivor["confidence"] = other["confidence"]
            point = survivor.get("enforcement_point")
            reason = (
                f"same enforcement point {point!r}"
                if point
                else f"same crossing {survivor.get('from')} -> {survivor.get('to')}, "
                "neither names a distinct enforcement point"
            )
            notes.append(f"{other['candidate_key']} merged into {survivor['candidate_key']} — {reason}")
        # A merge that spans components must say which ones it absorbed: the
        # surviving row names one endpoint, but the STRIDE dispatch, the
        # boundary-reference validator and the ingress elevation all ask "is this
        # finding's component adjacent to this boundary?". Without the record,
        # consolidating would silently REMOVE the elevation channel from every
        # component that got folded in.
        absorbed = sorted(
            {
                endpoint
                for member in members
                for endpoint in (member.get("from"), member.get("to"))
                if endpoint in components
            }
            # An endpoint a member already gave up (the client-tier source
            # rewritten to `external`) is still anchored here, so it must not
            # drop out when the group is recomputed.
            | {
                covered
                for member in members
                for covered in (member.get("covers_components") or [])
                if covered in components
            }
        )
        if len(absorbed) > 1:
            root = _deployable_root(survivor.get("to"), components)
            if _crossing_class(survivor) == "ingress" and root in absorbed and root != survivor.get("to"):
                notes.append(
                    f"{survivor['candidate_key']}: target {survivor.get('to')} -> {root} — "
                    "the merged crossings enter one deployable, which names the perimeter"
                )
                survivor["to"] = root
            survivor["covers_components"] = absorbed
        merged.append(survivor)

    order = {row["candidate_key"]: i for i, row in enumerate(candidates)}
    merged.sort(key=lambda row: order.get(row["candidate_key"], 10**9))
    return merged, alias, notes


_EVIDENCE_CONTEXT_RADIUS = 3


def _evidence_context(repo_root: Path, entry: dict, radius: int = _EVIDENCE_CONTEXT_RADIUS) -> str:
    """The cited line plus a small window, so a wrapped call still matches."""
    line_no = entry.get("line")
    if not isinstance(line_no, int):
        return ""
    lines = [
        _evidence_line(repo_root, {**entry, "line": probe})
        for probe in range(max(1, line_no - radius), line_no + radius + 1)
    ]
    return "".join(lines)


def _ingress_is_evidenced(repo_root: Path, candidate: dict) -> bool:
    """Does the cited evidence actually show the inbound surface it claims?

    `confirmed` is what unlocks the entire external-ingress severity channel:
    `appsec-stride-analyzer-v2` may only emit a `boundary_refs[]` entry for a
    confirmed boundary, and `triage_compute_ranking` only elevates on
    `confirmed` + `from == "external"`. Leaving that judgement wholly to the
    analyst made the channel unreachable on juice-shop — it marked exactly one
    boundary `confirmed` and that one was outbound, so zero of six boundaries
    were eligible and no finding could be elevated however strong its evidence.

    The check reads the CITED LINE (plus a small window for wrapped calls), not
    the whole file. A file-level scan asks a different question than the
    candidate answers: juice-shop's `server.ts` holds 172 route registrations, so
    every candidate citing it anywhere would pass regardless of what its own
    evidence points at. The direction correction next to this already demands the
    cited line, and it decides strictly less — the weaker check cannot be the one
    guarding the stronger effect.

    This only unlocks eligibility — elevation still requires a finding-owned
    reference carrying its own evidence, and stays capped at High.
    """
    return any(
        _ROUTE_REGISTRATION_RE.search(_evidence_context(repo_root, entry))
        for entry in candidate.get("evidence") or []
        if isinstance(entry, dict)
    )


def _looks_inbound(repo_root: Path, candidate: dict) -> bool:
    """True when the candidate's own evidence lands on a route registration.

    A pull endpoint (`app.get('/metrics')`) is an INGRESS crossing however the
    scraper is described in prose. Modelling it `component → external` both
    invents a third-party egress boundary and mis-renders it: `figure1_svg`
    routes any `to == "external"` row to an "outbound" note instead of a
    perimeter divider.
    """
    for entry in candidate.get("evidence") or []:
        if isinstance(entry, dict) and _ROUTE_REGISTRATION_RE.search(_evidence_line(repo_root, entry)):
            return True
    return False


def promote_candidates(
    *,
    repo_root: Path,
    output_dir: Path,
    candidates_path: Path,
    assessment_input_path: Path,
    prior_model: Path | None,
) -> tuple[dict, dict]:
    """Validate candidate coverage and promote candidates into the catalog.

    The LLM-authored file is never consumed by downstream stages. Public IDs,
    endpoint resolution, declaration merging, sources, and status remain owned
    by ``normalize``.
    """
    candidate_doc = _read_json(candidates_path, None)
    assessment = _read_json(assessment_input_path, None)
    if not isinstance(candidate_doc, dict) or not isinstance(assessment, dict):
        raise ValueError("candidate or assessment-input artifact is missing/malformed")
    for document, schema_path in (
        (candidate_doc, CANDIDATES_SCHEMA),
        (assessment, ASSESSMENT_INPUT_SCHEMA),
    ):
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(document)

    for field in ("component_inventory_fingerprint", "assessment_input_fingerprint"):
        if candidate_doc[field] != assessment[field]:
            raise ValueError(f"candidate {field} does not match immutable assessment input")

    component_ids = {row["id"] for row in assessment["components"]}
    signal_by_id = {row["id"]: row for row in assessment["signals"]}
    if len(signal_by_id) != len(assessment["signals"]):
        raise ValueError("assessment input contains duplicate signal IDs")
    candidates = candidate_doc["candidates"]
    candidate_by_key = {row["candidate_key"]: row for row in candidates}
    dispositions = candidate_doc["dispositions"]
    disposition_by_signal = {row["signal_id"]: row for row in dispositions}
    mandatory = {sid for sid, row in signal_by_id.items() if row.get("mandatory")}

    # The relational rules live in validate_fragment, so the authoring agent's
    # mandated self-check enforces exactly what this gate enforces — see the
    # docstring there for why they may not live here. Raising the first error
    # preserves the wording callers and tests match on.
    invariant_errors = fragment_invariant_errors(
        "trust-boundary-candidates", candidate_doc, context=assessment
    )
    if invariant_errors:
        raise ValueError(invariant_errors[0])

    dropped_candidates: dict[str, str] = {}
    candidates, candidate_alias, consolidation_notes = _consolidate_candidates(
        candidates,
        components={row["id"]: row for row in assessment["components"]},
        repo_root=repo_root,
        dropped=dropped_candidates,
    )
    candidate_by_key = {row["candidate_key"]: row for row in candidates}
    for note in consolidation_notes:
        print(f"trust-boundary-consolidation: {note}", file=sys.stderr)

    provisional_rows = []
    for candidate in candidates:
        row = {
            key: deepcopy(candidate[key])
            for key in ("name", "from", "to", "kind", "assumption", "evidence", "confidence")
        }
        # Carried, not dropped: without these the finished model cannot show why
        # two crossings became one row, and the next run cannot reproduce the
        # decision from `threat-model.yaml`.
        for optional in ("enforcement_point", "confidence_basis", "covers_components", "assumption_legs"):
            if candidate.get(optional):
                row[optional] = deepcopy(candidate[optional])
        row["evidence"] = _canonical_evidence(
            repo_root,
            row["evidence"],
            [],
            candidate["candidate_key"],
        )
        if row["confidence"] == "confirmed" and not row["evidence"]:
            raise ValueError(
                f"{candidate['candidate_key']} claims confirmed confidence without valid repository evidence"
            )
        provisional_rows.append(row)
    provisional = {"schema_version": 2, "trust_boundaries": provisional_rows}
    sidecar = output_dir / ".trust-boundaries.json"
    canonical, _warnings = normalize(
        repo_root=repo_root,
        sidecar=sidecar,
        prior_model=prior_model,
        output_dir=output_dir,
        raw_sidecar=provisional,
        destination=sidecar,
    )

    canonical_rows = canonical["trust_boundaries"]
    candidate_to_ids: dict[str, list[str]] = {}
    for key, candidate in candidate_by_key.items():
        exact = [
            row["id"]
            for row in canonical_rows
            if row.get("from") == candidate["from"]
            and row.get("to") == candidate["to"]
            and str(row.get("name", "")).casefold() == candidate["name"].casefold()
        ]
        if not exact:
            # `kind` joins the fallback: two crossings can share endpoints and
            # still ask different questions (the B2B `vm.createContext` sandbox
            # and the HTTPS perimeter are both `external -> backend-api`), so a
            # candidate whose name changed upstream must not claim both.
            exact = [
                row["id"]
                for row in canonical_rows
                if row.get("from") == candidate["from"]
                and row.get("to") == candidate["to"]
                and row.get("kind") == candidate.get("kind")
            ]
        if not exact:
            # normalize()'s _consolidate() may have folded the candidate's target
            # component into a parent boundary (covers_components lists the absorbed
            # sub-components).  Match on the folded-in component so a sub-component
            # candidate (e.g. external → realtime-channel folded into
            # external → backend-api) still resolves to a canonical boundary.
            exact = [
                row["id"]
                for row in canonical_rows
                if row.get("from") == candidate["from"] and candidate.get("to") in (row.get("covers_components") or [])
            ]
        candidate_to_ids[key] = sorted(set(exact), key=_numeric_id)
    # Dispositions still reference the pre-merge keys; point every alias at the
    # survivor so signal promotion resolves after consolidation.
    for original, survivor in candidate_alias.items():
        if original not in candidate_to_ids:
            candidate_to_ids[original] = list(candidate_to_ids.get(survivor, []))

    coverage_rows: list[dict] = []
    issues: list[dict] = []
    for signal_id in sorted(mandatory):
        disposition = disposition_by_signal[signal_id]
        boundary_ids = sorted(
            {boundary_id for key in disposition["candidate_keys"] for boundary_id in candidate_to_ids.get(key, [])},
            key=_numeric_id,
        )
        verdict = disposition["disposition"]
        rationale = disposition["rationale"]
        # A crossing removed as client-side is a REMOVAL, and a removal that only
        # showed up as a missing row would be invisible. The signal keeps its
        # place in the coverage report, its disposition is restated
        # deterministically as `same-trust` — both ends of the crossing sit
        # outside the trust perimeter — and the reason is written where a reader
        # can audit it.
        if verdict == "boundary" and not boundary_ids and disposition["candidate_keys"]:
            reasons = [dropped_candidates[key] for key in disposition["candidate_keys"] if key in dropped_candidates]
            if len(reasons) == len(disposition["candidate_keys"]):
                verdict = "same-trust"
                rationale = _clean_text(reasons[0], fallback=rationale, limit=300)
                issues.append(
                    {
                        "code": "client-tier-crossing-dropped",
                        "signal_id": signal_id,
                        "message": _clean_text(
                            f"No trust boundary was recorded for this signal. {reasons[0]}",
                            fallback="Crossing into client-tier code is not a trust boundary.",
                            limit=300,
                        ),
                    }
                )
        if verdict == "boundary" and not boundary_ids:
            raise ValueError(f"{signal_id} did not promote to a canonical boundary")
        if verdict == "unresolved":
            issues.append(
                {
                    "code": "unresolved-signal",
                    "signal_id": signal_id,
                    "message": "The analyst accounted for this signal but could not resolve its trust disposition.",
                }
            )
        coverage_rows.append(
            {
                "signal_id": signal_id,
                "disposition": verdict,
                "candidate_keys": [key for key in disposition["candidate_keys"] if key not in dropped_candidates],
                "boundary_ids": boundary_ids,
                "evidence": signal_by_id[signal_id]["evidence"],
                "rationale": rationale,
            }
        )
    # Visibility instead of a required field. Making `enforcement_point`
    # mandatory would buy presence, not specificity: the predictable filler
    # ("application code") groups by a string that ignores endpoints, so it
    # merges unrelated crossings silently, while an omitted one degrades into the
    # conservative, visible crossing fallback. Report the gap and let the next
    # run close it.
    without_point = sorted(row["candidate_key"] for row in candidates if not row.get("enforcement_point"))
    for candidate_key in without_point:
        issues.append(
            {
                "code": "missing-enforcement-point",
                "candidate_key": candidate_key,
                "message": (
                    "No specific enforcement point was named, so this crossing was consolidated by its "
                    "endpoints alone. Naming the control keeps genuinely distinct crossings apart."
                ),
            }
        )
    coverage = {
        "schema_version": 1,
        "component_inventory_fingerprint": assessment["component_inventory_fingerprint"],
        "assessment_input_fingerprint": assessment["assessment_input_fingerprint"],
        "status": "pass",
        "signals": coverage_rows,
        "issues": issues,
    }
    schema = json.loads(COVERAGE_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(coverage)
    atomic_write_json(output_dir / ".trust-boundary-coverage.json", coverage, sort_keys=False)
    return canonical, coverage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    norm = sub.add_parser("normalize")
    norm.add_argument("--repo-root", type=Path, required=True)
    norm.add_argument("--sidecar", type=Path, required=True)
    norm.add_argument("--prior-model", type=Path)
    norm.add_argument("--output-dir", type=Path, required=True)
    ctx = sub.add_parser("contexts")
    ctx.add_argument("--repo-root", type=Path, required=True)
    ctx.add_argument("--output-dir", type=Path, required=True)
    ctx.add_argument("--depth", choices=("quick", "standard", "thorough"), required=True)
    ctx.add_argument("--component", action="append", default=[])
    promote = sub.add_parser("promote")
    promote.add_argument("--repo-root", type=Path, required=True)
    promote.add_argument("--output-dir", type=Path, required=True)
    promote.add_argument("--candidates", type=Path, required=True)
    promote.add_argument("--assessment-input", type=Path, required=True)
    promote.add_argument("--prior-model", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == "normalize":
            result, warnings = normalize(
                repo_root=args.repo_root,
                sidecar=args.sidecar,
                prior_model=args.prior_model,
                output_dir=args.output_dir,
            )
            print(json.dumps({"boundaries": len(result["trust_boundaries"]), "warnings": len(warnings)}))
        elif args.operation == "contexts":
            audit = prepare_contexts(
                repo_root=args.repo_root,
                output_dir=args.output_dir,
                component_ids=args.component,
                depth=args.depth,
            )
            print(json.dumps({"components": len(audit["components"])}))
        else:
            canonical, coverage = promote_candidates(
                repo_root=args.repo_root,
                output_dir=args.output_dir,
                candidates_path=args.candidates,
                assessment_input_path=args.assessment_input,
                prior_model=args.prior_model,
            )
            print(
                json.dumps(
                    {
                        "boundaries": len(canonical["trust_boundaries"]),
                        "signals": len(coverage["signals"]),
                        "unresolved": len(coverage["issues"]),
                    }
                )
            )
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        print(f"prepare_trust_boundary_context: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
