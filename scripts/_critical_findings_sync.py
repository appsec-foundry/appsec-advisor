"""Keep ``critical_findings[].mitigation_id`` in step with ``threats[]``.

``build_threat_model_yaml.build_critical_findings`` derives each entry's
``mitigation_id`` from that threat's ``mitigation_ids[0]`` and writes the yaml.
The auto-emitter pass (``auto_emitter_pass.sh``) then runs *after* the builder
and rewrites ``threats[].mitigation_ids`` — ``emit_config_scan_mitigations``,
``emit_finding_fix_mitigations`` and ``emit_review_mitigations`` all mint fresh
M-IDs and relink findings to them. None of them knew about ``critical_findings``,
so the curated worst-case list kept the builder's now-stale ids.

Observed impact: in two real models every single entry was wrong (30/30 and
12/12) — the list still paired T-001→M-001, T-002→M-002 positionally while the
threats had been relinked to the emitter-minted M-010+. Consumers that read
``critical_findings`` (``summarize_threat_model``, ``query_threat_model``,
``review_threat_model``) then cite a fix that has nothing to do with the
finding: F-003 "Insecure JWT Verification" pointed at "Apply least-privilege
permissions" instead of "Enforce JWT signature and algorithm verification".

This resyncs the derived field only. Membership of the list stays the builder's
decision — an emitter has no business adding or dropping a curated worst case.
"""

from __future__ import annotations


def resync_critical_findings(data: dict) -> int:
    """Re-derive ``critical_findings[].mitigation_id`` from ``threats[]``.

    Call this immediately before persisting a yaml whose
    ``threats[].mitigation_ids`` were changed. Returns the number of entries
    corrected (0 when already consistent), so a caller can log it.

    An entry whose threat no longer exists is left untouched — that is a
    dangling-reference problem for the composer's link checker to report, not
    something to silently paper over here.
    """
    cf = data.get("critical_findings")
    if not isinstance(cf, list):
        return 0

    first_by_threat: dict[str, str | None] = {}
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id") or "").strip()
        if not tid:
            continue
        mids = [str(m).strip() for m in (t.get("mitigation_ids") or []) if str(m).strip()]
        first_by_threat[tid] = mids[0] if mids else None

    fixed = 0
    for entry in cf:
        if not isinstance(entry, dict):
            continue
        tid = str(entry.get("threat_id") or "").strip()
        if tid not in first_by_threat:
            continue
        want = first_by_threat[tid]
        if entry.get("mitigation_id") != want:
            entry["mitigation_id"] = want
            fixed += 1
    return fixed
