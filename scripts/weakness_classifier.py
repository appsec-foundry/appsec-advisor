"""Canonical weakness-class classifier.

Single source of truth for mapping a CWE (or a threat dict) to one of the
`data/weakness-classes.yaml` cluster ids (injection, broken_auth,
missing_authz, weak_crypto, server_side_exposure, output_xss_csp,
sensitive_disclosure, dos, outdated_deps, or the `_unmapped` catch-all).

Shared by the threat merger's weakness reconciler (merge_threats.py) and the
composer (compose_threat_model.py) so both group findings by the SAME class
map — P1 of the weakness-class evidence model
(docs/internal/analysis/implplan-weakness-class-evidence-model.md).

qa_checks.py deliberately keeps its own self-contained copy (it avoids
cross-module imports by design); keep the CWE→cluster logic here identical.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Shared across every classifier caller so the "CWE matches N clusters" hazard
# warning fires at most once per CWE per process. The composer aliases this set
# as `_MULTI_MATCH_WARNED` so its call sites (and tests) mutate the same object.
MULTI_MATCH_WARNED: set[str] = set()

_CACHE: dict[str, Any] | None = None


def load_weakness_classes() -> dict[str, Any]:
    """Lazy-load and cache the weakness-classes vocabulary.

    Missing/malformed file → empty vocabulary (every threat becomes
    `_unmapped`), matching the composer/qa fallbacks.
    """
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    candidate = Path(__file__).resolve().parent.parent / "data" / "weakness-classes.yaml"
    if not candidate.exists():
        _CACHE = {"clusters": []}
        return _CACHE
    import yaml as _yaml

    try:
        _CACHE = _yaml.safe_load(candidate.read_text()) or {"clusters": []}
    except Exception:
        _CACHE = {"clusters": []}
    return _CACHE


def classify_cwe(cwe: str, vocab: dict | None = None, *, warn: bool = True) -> str:
    """Return the weakness-cluster id for a CWE string.

    First-match-by-file-order wins when a CWE is listed in more than one
    cluster (deterministic). With ``warn=True`` a one-time stderr warning is
    emitted per ambiguous CWE (the composer surfaces the routing hazard);
    ``warn=False`` mirrors qa_checks' quiet lookup.
    """
    vocab = vocab or load_weakness_classes()
    cwe = (cwe or "").strip().upper()
    if not cwe:
        return "_unmapped"
    matches: list[str] = []
    for cluster in vocab.get("clusters") or []:
        if cluster.get("id") == "_unmapped":
            continue
        if cwe in {c.strip().upper() for c in (cluster.get("cwes") or [])}:
            matches.append(cluster["id"])
    if not matches:
        return "_unmapped"
    if warn and len(matches) > 1 and cwe not in MULTI_MATCH_WARNED:
        MULTI_MATCH_WARNED.add(cwe)
        sys.stderr.write(
            f"weakness_classifier: WARNING — {cwe} matches multiple weakness "
            f"clusters {matches}; first-match wins ({matches[0]}). Remove the "
            f"CWE from all but one cluster in data/weakness-classes.yaml to make "
            f"routing deterministic.\n"
        )
    return matches[0]


def classify_threat(threat: dict, vocab: dict | None = None, *, warn: bool = True) -> str:
    """Weakness-cluster id for a threat dict (keyed on its ``cwe`` field)."""
    return classify_cwe((threat or {}).get("cwe") or "", vocab, warn=warn)
