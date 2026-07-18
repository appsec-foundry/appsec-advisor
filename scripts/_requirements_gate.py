"""Shared gate for *explicit custom* requirements integrated into a scan.

Both read-only consumers of a finished ``threat-model.yaml`` need the same
answer to "did this team wire up their own requirement catalog, and which IDs
did they declare?" — ``review_threat_model.py`` for its requirements badge/lens,
``query_threat_model.py`` for answering questions about requirement violations.

The gate lives here so the two cannot drift: the exclusions below (skipped stub,
bundled OWASP fallback, check switched off) decide whether a *requirement*
signal is shown at all, and a consumer that got them subtly wrong would either
invent compliance claims or hide real violations.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

_EMPTY: dict = {"integrated": False, "ids": set(), "url_by_id": {}, "checked": False, "source": ""}


def _empty(checked: bool = False, source: str = "") -> dict:
    return dict(_EMPTY, checked=checked, source=source)


def load_requirements(output_dir: Path, meta: dict) -> dict:
    """Gate + declared custom requirement IDs.

    The signal is reported ONLY for *explicit* custom requirements a team
    integrated — never the bundled OWASP best-practices baseline, never a
    skipped stub, and never when the requirements check was off for the run.
    Signals (all read-only):

      * ``meta.check_requirements`` — the run activated the check.
      * ``<output-dir>/.requirements.yaml`` ``source`` — ``skipped`` (stub) and
        ``bundled-bestpractices`` (zero-config OWASP fallback) are both
        excluded; anything else (company catalog / cache / URL) is a real
        custom source.
      * non-empty ``categories`` — a source that actually declares requirements.

    Returns ``{integrated, ids, url_by_id, checked, source}``. ``integrated`` is
    False (and ids empty) whenever any signal fails, so the caller shows no
    *custom* requirement signal.

    ``checked``/``source`` exist so a caller can tell the two "no signal" cases
    apart. ``checked=True, integrated=False`` means the run DID run a
    requirements check but against the bundled baseline (or a skipped stub) —
    reporting that as silence reads as "checked, nothing violated", which is a
    false compliance claim. Callers must say which one it was.
    """
    checked = bool(meta.get("check_requirements"))
    if not checked:
        return _empty()
    path = output_dir / ".requirements.yaml"
    try:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_YAML_LOADER) or {}
    except (OSError, yaml.YAMLError):
        return _empty(checked=True)
    if not isinstance(doc, dict):
        return _empty(checked=True)
    source = str(doc.get("source") or "").strip().lower()
    cats = doc.get("categories") or []
    if source in ("skipped", "bundled-bestpractices") or not isinstance(cats, list) or not cats:
        return _empty(checked=True, source=source)
    ids: set[str] = set()
    url_by_id: dict[str, str] = {}
    for cat in cats:
        if not isinstance(cat, dict):
            continue
        for req in cat.get("requirements") or []:
            if not isinstance(req, dict):
                continue
            rid = str(req.get("id") or "").strip()
            if rid:
                ids.add(rid)
                url_by_id.setdefault(rid, str(req.get("url") or "").strip())
    if not ids:
        return _empty(checked=True, source=source)
    return {"integrated": True, "ids": ids, "url_by_id": url_by_id, "checked": True, "source": source}


def violated_requirements(threat: dict) -> list[str]:
    """Requirement IDs a threat evidences — the canonical ``violated_requirements``
    array plus a single ``requirement_id``, order-preserving + de-duplicated.

    This is the finding->requirement direction only. The authoritative
    requirement->finding->mitigation traceability table stays in the rendered
    report; a consumer needs "does this finding break a custom requirement".
    """
    out: list[str] = []
    seen: set[str] = set()
    for rid in threat.get("violated_requirements") or []:
        rid = str(rid).strip()
        if rid and rid not in seen:
            seen.add(rid)
            out.append(rid)
    single = str(threat.get("requirement_id") or "").strip()
    if single and single not in seen:
        out.append(single)
    return out
