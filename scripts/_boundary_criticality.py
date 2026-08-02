"""_boundary_criticality.py — how much a trust boundary matters to the reader.

A model can resolve a dozen boundaries, and a catalogue that presents them as a
flat list makes the reader weigh an outbound CI-registry push the same as the
unauthenticated internet edge in front of the API. This module is the one place
that ranks them, so the §1 catalogue, the delivered `tb-N` numbering and the
figures all agree on which boundaries lead.

The axis is exposure and direction, not finding count: inbound from the internet
is where an unauthenticated attacker starts, an internal component-to-component
crossing needs a foothold first, and an outbound crossing is reached only after
the process is already trusted. Linked findings break ties — evidence of a real
gap outranks a clean boundary at the same exposure — but they do not lead, because
which boundary happens to carry a `boundary_refs[]` entry is noisy.

`exposure_of` is the shared classifier (it used to live only in the composer,
where the yaml builder and the figures could not reach it).
"""

from __future__ import annotations

from prepare_trust_boundary_context import boundary_endpoints_valid

# Rank, most exposed first — what numbering and figure prominence follow. The
# WORDS a reader sees live in `_RATINGS` alone: this table used to carry a
# second set ("unconfirmed" against the rating's "Unverified"), and once both
# surfaces rendered, one boundary was graded in two vocabularies (user
# 2026-08-01).
_TIERS: dict[str, int] = {
    "review required": 0,
    "internet-facing": 1,
    "inferred": 2,
    "internal": 3,
    "outbound": 4,
}


def exposure_of(row: dict, component_ids: set[str]) -> str:
    """Classify a boundary row as internet-facing / outbound / internal /
    inferred / review required."""
    if not isinstance(row, dict):
        return "review required"
    if row.get("resolution_status") in {"unresolved", "conflicted"}:
        return "review required"
    if not boundary_endpoints_valid(row, component_ids):
        return "review required"
    if row.get("confidence") != "confirmed":
        return "inferred"
    source, target = row.get("from"), row.get("to")
    if source == "external" and target in component_ids:
        return "internet-facing"
    if source in component_ids and target == "external":
        return "outbound"
    if source in component_ids and target in component_ids:
        return "internal"
    return "review required"


# Reader-facing rating, keyed by exposure.
#
# Three deliberate choices, all easy to erode later:
#
# 1. It rates REACHABILITY, not linked findings. Only a fraction of findings
#    carry a `boundary_refs[]` entry, so a findings-weighted rating would mark a
#    boundary as safer merely because nothing happened to link to it — and would
#    rate an unexamined boundary below an examined one. Linked findings stay
#    their own column.
# 2. The vocabulary is exposure-native — never Critical/High/Medium/Low and
#    never the 🔴🟠🟡🟢 dots. Those belong to FINDING SEVERITY elsewhere in the
#    report, and reusing either the words or the glyphs for a different concept
#    invites a reader to see "🔴" on a boundary row and conclude a critical
#    finding lives there. No glyph carries two meanings.
# 3. Each word claims only what `exposure_of` above establishes, which is one
#    thing: whether the far end is a modelled component. The top tier read
#    "Public", asserting an audience the rule never checks — internet, partner
#    network and corporate LAN are indistinguishable to it (user 2026-08-02).
#    "Exposed" was the first replacement considered and is the same error one
#    step milder: it fits the column's NAME but states a risk posture the rule
#    did not establish. "External" states the rule itself, and pairs with
#    Internal — both say where the other end sits, and the tier ORDER carries
#    the risk judgment. Where the report needs proven internet reach, the
#    severity-elevation rule tests for it separately.
_RATINGS: dict[str, tuple[str, str]] = {
    "review required": ("⚠", "Review"),
    "internet-facing": ("🌐", "External"),
    "inferred": ("◐", "Unverified"),
    "internal": ("🔒", "Internal"),
    "outbound": ("↗", "Egress"),
}


def tier_of(exposure: str) -> int:
    """Rank tier for an exposure string; unknown values sort last."""
    return _TIERS.get(exposure, 9)


def rating_of(exposure: str) -> tuple[str, str]:
    """`(glyph, word)` exposure rating — what a reader scans to see which
    boundaries lead. Unknown values fall back to the review rating so an
    unclassifiable row is never presented as benign."""
    return _RATINGS.get(exposure, ("⚠", "Review"))


def label_of(exposure: str) -> str:
    """Badge text where a glyph does not travel — the SVG figure, whose fonts
    are the render pipeline's problem rather than the Markdown's. The word is
    the rating's own, so a boundary reads the same in the figure and in §1."""
    return rating_of(exposure)[1]


def facts_of(data: dict) -> dict[str, dict]:
    """`tb-N` → `{"id", "crossing", "exposure"}` for a delivered `threat-model.yaml`.

    What an export needs to make a boundary reference mean something outside
    this repository. A `tb-N` on its own does not: the number is renumbered per
    run, so a SARIF consumer or a Threat Dragon reader received an opaque token
    (user 2026-08-01). Resolving it here rather than per export keeps every
    artifact on the same crossing text and the same `exposure_of` verdict as the
    report's Exposure column.
    """
    component_ids = {
        row["id"] for row in data.get("components") or [] if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    facts: dict[str, dict] = {}
    for row in data.get("trust_boundaries") or []:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            continue
        facts[row["id"]] = {
            "id": row["id"],
            "crossing": f"{row.get('from') or '?'} → {row.get('to') or '?'}",
            "exposure": exposure_of(row, component_ids),
        }
    return facts
