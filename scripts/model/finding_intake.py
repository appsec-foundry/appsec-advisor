"""model/finding_intake.py — the one place a producer's raw intake becomes a threat record's
component and tier fields (decision FE-22).

Every producer of a threat record — STRIDE flattening, the Config/IaC and source
scanners, design signals, abuse-case promotion — states two *claims* and nothing
final:

* ``dispatch_component`` — the component the producer worked under or guessed from
  a path. A hint: the finalize pass decides the component.
* ``claimed_tier`` — the producer's evidence-basis claim (``confirmed-exploitable``
  or ``insecure-practice``). A claim: the finalize pass derives the tier from the
  verification verdict.

``apply_intake`` records both and derives the established ``component_id``,
``component_name`` and ``evidence_tier`` from them exactly as each producer always
did, so a record reads the same to every consumer until the finalize pass owns
those fields. Producers call this instead of writing the three fields themselves;
a source-scan guard keeps it that way.
"""

from __future__ import annotations

CLAIMED_TIERS = frozenset({"confirmed-exploitable", "insecure-practice"})


def apply_intake(
    threat: dict,
    *,
    dispatch_component: str | None,
    component_name: str | None = None,
    claimed_tier: str | None = None,
    keep_existing: bool = False,
) -> dict:
    """Record a producer's intake claims on ``threat`` and derive the legacy fields.

    ``keep_existing`` keeps a ``component_id`` / ``component_name`` the record
    already carries (a STRIDE analyzer may name its own); otherwise the dispatch
    component is authoritative. A ``claimed_tier`` outside ``CLAIMED_TIERS`` is
    ignored, leaving ``evidence_tier`` to the downstream default. Returns ``threat``.
    """
    if dispatch_component is not None:
        threat["dispatch_component"] = dispatch_component
        if keep_existing:
            threat.setdefault("component_id", dispatch_component)
        else:
            threat["component_id"] = dispatch_component
    if component_name is not None:
        if keep_existing:
            threat.setdefault("component_name", component_name)
        else:
            threat["component_name"] = component_name
    if claimed_tier in CLAIMED_TIERS:
        threat["claimed_tier"] = claimed_tier
        threat["evidence_tier"] = claimed_tier
    return threat
