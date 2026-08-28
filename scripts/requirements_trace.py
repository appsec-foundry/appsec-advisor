"""requirements_trace.py — single source of truth for requirement traceability
and blueprint selection.

Two rules were previously implemented once per surface and drifted:

  * **Which requirements a threat evidences.** ``build_threat_model_yaml.py``
    read only ``threats[].violated_requirements``, while
    ``compose_threat_model.py`` also recovered the legacy singular
    ``requirement_id`` and any declared ID an analyzer parked in
    ``remediation.reference``. The YAML and the rendered §10 block therefore
    disagreed for a quarter of the mitigations in a run, and in some cases
    the two sets were disjoint. `requirement_ids_for_threat` is now the only
    implementation; both call it.

  * **Which blueprint prescribes a mitigation.** The renderer grouped the
    catalog's blueprint sections by insertion order of the fulfilled
    requirements and rendered the first group, ranking only the sections
    *inside* it. A mass-assignment fix therefore surfaced an
    authorization blueprint because its first fulfilled requirement happened
    to be an access-control one, while the catalog's "Unexpected Field
    Handling" section — the guidance actually written for that case — was
    demoted to a footnote. `select_blueprint` ranks the groups themselves
    and reports the winning score, so a caller can tell a real match from an
    arbitrary one.

The catalog shape this module reads is the one `fetch_requirements.py`
persists as ``$OUTPUT_DIR/.requirements.yaml``::

    blueprints:
      - id: BP-…
        title: …
        url: …                     # blueprint landing page
        sections:
          - title: …
            url: …                 # the page this section lives on
            content: |
              …prescriptive prose…
            references:
              - id: REQ-ID         # or a bare "REQ-ID" string

``references[].id`` is the requirement↔blueprint cross-reference: it names
the requirement the section prescribes an implementation for.

Consumers:

  * ``scripts/compose_threat_model.py`` — §7b Guidance column and the §10
    per-mitigation Blueprint block.
  * ``scripts/build_threat_model_yaml.py`` — ``mitigations[].blueprint`` and
    ``mitigations[].fulfills_requirements`` in the structured model.
  * ``scripts/build_requirements_contexts.py`` — the per-requirement
    ``blueprint_guidance`` the STRIDE analyzers receive, so the prescribed
    implementation reaches the analysis instead of only the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# One bullet's worth of prescription. Catalog sections are multi-line prose;
# every consumer needs a single bounded line, so the cut happens here once.
MAX_SECTION_CHARS = 220

# The analyst slice is charged per component and per token, so it carries a
# tighter excerpt than the report does.
MAX_ANALYST_SECTION_CHARS = 200

# Sections shown under one blueprint heading before the rest are counted off.
MAX_SECTIONS_RENDERED = 3

# Blueprint groups expanded per mitigation. Several blueprints can legitimately
# prescribe the same requirement (an end-user and a service-to-service one both
# cover JWT validation) with near-identical wording; expanding them all doubles
# the block for no added instruction. The rest are named, not expanded.
MAX_BLUEPRINTS_RENDERED = 1

_RANK_STOPWORDS = frozenset(
    "the that this these those and any all each other with from into within must should "
    "your their there when where which what while have been will need must also only "
    "use used using ensure apply applies against before after every both such than then".split()
)


def significant_terms(text: str) -> set[str]:
    """Lower-cased content words of four or more characters, stopwords removed."""
    return {w for w in re.findall(r"[a-z][a-z0-9-]{3,}", (text or "").lower()) if w not in _RANK_STOPWORDS}


def section_excerpt(raw: Any, limit: int = MAX_SECTION_CHARS) -> str:
    """One-line, length-bounded prescription text from a blueprint section.

    Cuts at a sentence end when one falls in the back half, else at a word
    boundary, so the prescription never ends mid-word.
    """
    text = re.sub(r"\s+", " ", str(raw or "")).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    dot = cut.rfind(". ")
    if dot >= limit // 2:
        return cut[: dot + 1]
    return (cut.rsplit(" ", 1)[0].rstrip(",;:") or cut) + "…"


@dataclass(frozen=True)
class BlueprintSection:
    """One prescriptive section of one blueprint, with both of its URLs.

    ``url`` is the page the section itself lives on and is what a reader must
    follow to find the quoted text; ``blueprint_url`` is the blueprint's own
    landing page. They differ routinely — a single blueprint cites several
    OWASP cheat sheets — so a consumer that shows section text must link
    ``url``, not ``blueprint_url``.
    """

    blueprint_id: str
    blueprint_title: str
    blueprint_url: str
    title: str
    url: str
    content: str


@dataclass
class SelectedBlueprint:
    """The blueprint a caller should present, plus what it beat."""

    blueprint_id: str
    blueprint_title: str
    blueprint_url: str
    sections: list[BlueprintSection]
    requirement_ids: list[str]
    score: int
    other_blueprint_ids: list[str] = field(default_factory=list)

    @property
    def is_grounded(self) -> bool:
        """True when the selection rests on wording shared with the mitigation.

        A zero score means no section of any candidate blueprint shares a
        single content word with the mitigation and its findings: the pick is
        then whichever the catalog happened to list first. Callers must not
        present such a selection as governing guidance.
        """
        return self.score > 0


def load_catalog(output_dir: Path) -> dict[str, Any]:
    """Parse ``$OUTPUT_DIR/.requirements.yaml``; ``{}`` when absent or broken.

    Requirements are optional, so every failure degrades to "no catalog"
    rather than stopping a run.
    """
    path = Path(output_dir) / ".requirements.yaml"
    if not path.is_file():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


def sections_by_requirement(
    catalog: dict[str, Any], limit: int = MAX_SECTION_CHARS
) -> dict[str, list[BlueprintSection]]:
    """Requirement ID → the blueprint sections that prescribe how to satisfy it.

    A ``references[]`` entry may be a mapping with an ``id`` or a bare ID
    string; both forms occur in published catalogs.
    """
    out: dict[str, list[BlueprintSection]] = {}
    for bp in catalog.get("blueprints") or []:
        if not isinstance(bp, dict):
            continue
        bid = str(bp.get("id") or "").strip()
        if not bid:
            continue
        bp_url = str(bp.get("url") or "").strip()
        for sec in bp.get("sections") or []:
            if not isinstance(sec, dict):
                continue
            entry = BlueprintSection(
                blueprint_id=bid,
                blueprint_title=str(bp.get("title") or "").strip(),
                blueprint_url=bp_url,
                title=str(sec.get("title") or "").strip(),
                url=str(sec.get("url") or "").strip() or bp_url,
                content=section_excerpt(sec.get("content"), limit),
            )
            for ref in sec.get("references") or []:
                rid = str((ref.get("id") if isinstance(ref, dict) else ref) or "").strip()
                if rid:
                    out.setdefault(rid, []).append(entry)
    return out


# The mitigation's own title names the change being made ("Allowlist
# client-controlled fields"); the findings' scenarios describe the attack around
# it and share vocabulary with far more sections. Weighting the title higher is
# what separates a blueprint written for this fix from one that merely discusses
# the same subsystem.
_PRIMARY_WEIGHT = 2


@dataclass(frozen=True)
class RankContext:
    """What a blueprint section is scored against.

    ``primary`` is the mitigation's own title, ``secondary`` the titles and
    scenarios of the findings it addresses.
    """

    primary: str = ""
    secondary: str = ""

    def terms(self) -> tuple[set[str], set[str]]:
        return significant_terms(self.primary), significant_terms(self.secondary)

    def is_empty(self) -> bool:
        return not (self.primary.strip() or self.secondary.strip())


def _section_score(section: BlueprintSection, primary: set[str], secondary: set[str]) -> int:
    section_terms = significant_terms(f"{section.title} {section.content}")
    return _PRIMARY_WEIGHT * len(primary & section_terms) + len(secondary & section_terms)


def rank_sections(sections: list[BlueprintSection], context: RankContext) -> list[BlueprintSection]:
    """Order sections by weighted content-word overlap; ties keep catalog order.

    One requirement is often prescribed by several sections of one blueprint —
    ``AC-002`` covers both method-level and resource-level authorization — and
    catalog order alone surfaces whichever comes first, which under an
    ownership fix is the wrong one.
    """
    if context.is_empty():
        return list(sections)
    primary, secondary = context.terms()
    return sorted(sections, key=lambda s: -_section_score(s, primary, secondary))


def select_blueprint(
    by_requirement: dict[str, list[BlueprintSection]],
    requirement_ids: list[str],
    context: RankContext,
) -> SelectedBlueprint | None:
    """Pick the blueprint that best fits ``context`` among those prescribing
    ``requirement_ids``.

    Grouping alone is not a selection: the group that wins must be the one
    whose best section actually matches the work at hand, not the group of
    whichever requirement the caller happened to list first. Ties keep the
    order the requirements were given in, which is the catalog's own order.

    Returns ``None`` when no listed requirement has a blueprint section.
    """
    groups: dict[str, dict[str, Any]] = {}
    for rid in requirement_ids:
        for sec in by_requirement.get(rid, []):
            grp = groups.setdefault(sec.blueprint_id, {"sections": [], "requirements": []})
            if rid not in grp["requirements"]:
                grp["requirements"].append(rid)
            if not any(s.title == sec.title for s in grp["sections"]):
                grp["sections"].append(sec)
    if not groups:
        return None

    primary, secondary = context.terms()
    order = list(groups)

    def group_score(bid: str) -> int:
        return max((_section_score(s, primary, secondary) for s in groups[bid]["sections"]), default=0)

    ranked = sorted(order, key=lambda bid: (-group_score(bid), order.index(bid)))
    winner = ranked[0]
    sections = rank_sections(groups[winner]["sections"], context)
    return SelectedBlueprint(
        blueprint_id=winner,
        blueprint_title=sections[0].blueprint_title if sections else "",
        blueprint_url=sections[0].blueprint_url if sections else "",
        sections=sections,
        requirement_ids=list(groups[winner]["requirements"]),
        score=group_score(winner),
        other_blueprint_ids=ranked[1:],
    )


def requirement_ids_for_threat(threat: dict[str, Any], known_ids: dict[str, str] | set[str] | None) -> list[str]:
    """Requirement IDs a threat evidences — order-preserving, de-duplicated.

    Sources, in order: the canonical ``violated_requirements[]`` array, the
    legacy singular ``requirement_id``, and — when ``known_ids`` is non-empty —
    any declared requirement ID found in ``remediation.reference``, whether the
    analyzer wrote it bracketed (``[ID]`` / ``[ID](url)``) or bare (``IF-002``).
    This closes the field-name split: STRIDE analyzers write a matched
    requirement into ``remediation.reference`` instead of the array, so the
    finding shows in §8 (``Violated:``) but was invisible to the §7b/§MS table.
    Matching against the declared-ID set keeps this prefix-agnostic and ignores
    OWASP/CWE references (they are not declared requirement IDs).

    An analyzer-declared ID is still only a claim; the catalog decides what the
    organisation actually requires. Unknown IDs are dropped whenever a catalog
    was loaded, so an invented or stale requirement cannot be presented as a
    broken commitment.
    """
    known = known_ids or {}
    out: list[str] = []

    def _add(rid: Any) -> None:
        s = str(rid or "").strip()
        if s and s not in out:
            out.append(s)

    def _declared(rid: Any) -> bool:
        return not known or str(rid or "").strip() in known

    for rid in threat.get("violated_requirements") or []:
        if _declared(rid):
            _add(rid)
    if threat.get("requirement_id") and _declared(threat["requirement_id"]):
        _add(threat["requirement_id"])
    if known:
        rem = threat.get("remediation") if isinstance(threat.get("remediation"), dict) else {}
        ref = rem.get("reference") if isinstance(rem, dict) else None
        if isinstance(ref, str) and ref:
            # Bracketed tokens first (preserves reference order for `[ID](url)`).
            for tok in re.findall(r"\[([^\]]+)\]", ref):
                if tok.strip() in known:
                    _add(tok)
            # Bare IDs: analyzers sometimes write `IF-002` without the brackets
            # the matcher above keys on. Only IDs in `known` match, so CWE/OWASP
            # refs never do; the word-boundary guard avoids partial hits.
            for kid in known:
                if kid not in out and re.search(r"(?<![\w-])" + re.escape(kid) + r"(?![\w-])", ref):
                    _add(kid)
    return out


def catalog_requirement_ids(catalog: dict[str, Any]) -> dict[str, str]:
    """Declared requirement ID → its source URL (``""`` when the catalog has none)."""
    out: dict[str, str] = {}
    for category in catalog.get("categories") or []:
        if not isinstance(category, dict):
            continue
        for req in category.get("requirements") or []:
            if not isinstance(req, dict):
                continue
            rid = str(req.get("id") or "").strip()
            if rid and rid not in out:
                out[rid] = str(req.get("url") or "").strip()
    return out
