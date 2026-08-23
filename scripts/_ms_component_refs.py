"""Canonical slug -> C-NN normalisation for Management Summary fragments.

The MS fragment schemas require component references in the canonical
``^C-\\d{2,}$`` form, but ``threat-model.yaml`` carries slug-style component ids
(``auth-identity``) in practice — ``compose_threat_model._component_lookup``
synthesises ``C-NN`` from the array order precisely because of that. A renderer
reading the yaml therefore tends to echo the slug it saw, which the schema
rejects (observed: anti-patterns 2026-06-12, ai-exposure 2026-06-21 juice-shop).

``compose_threat_model`` repairs this before it validates. The controller's
standalone pre-render gate (``validate_fragment.py pre-render-gate``) runs
*before* compose and did not, so it rejected fragments compose would have
accepted — a false blocking failure that consumed both repair retries while a
direct compose run succeeded (2026-08-22). Both callers now share this module so
the gate can never again be stricter than the composer it guards.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_CANONICAL_RE = re.compile(r"^C-\d+$")

# MS fragments carrying component references, and the list key holding them.
MS_FRAGMENT_LIST_KEYS: dict[str, str] = {
    "ms-anti-patterns.json": "anti_patterns",
    "ms-ai-exposure.json": "ai_risks",
}


def slug_to_cnn_map(components: Any) -> dict[str, str]:
    """Build a lower-cased {component-id-or-slug -> canonical C-NN} lookup.

    The ``C-{idx:02d}`` assignment follows the component array order, identical
    to ``compose_threat_model._component_lookup``, so anchors stay consistent.
    """
    cmap: dict[str, str] = {}
    for idx, component in enumerate(components or [], start=1):
        if not isinstance(component, dict):
            continue
        raw = (component.get("id") or "").strip()
        canonical = raw if _CANONICAL_RE.match(raw) else f"C-{idx:02d}"
        if raw:
            cmap[raw.lower()] = canonical
        cmap[canonical.lower()] = canonical
    return cmap


def normalize_refs(refs: Any, cmap: dict[str, str]) -> tuple[Any, bool]:
    """Return (normalised refs, changed?) for an ``affected_components`` list.

    Accepts the bare-string form (``"backend-api"``) and the ``{id, name}`` dict
    form the schemas permit. An already-canonical or unknown ref is left
    untouched so the schema still catches genuine garbage.
    """
    if not isinstance(refs, list):
        return refs, False
    new_refs: list[Any] = []
    changed = False
    for ref in refs:
        if isinstance(ref, str):
            canonical = cmap.get(ref.strip().lower())
            if canonical and canonical != ref:
                new_refs.append(canonical)
                changed = True
                continue
        elif isinstance(ref, dict) and isinstance(ref.get("id"), str):
            canonical = cmap.get(ref["id"].strip().lower())
            if canonical and canonical != ref["id"]:
                ref = {**ref, "id": canonical}
                changed = True
        new_refs.append(ref)
    return new_refs, changed


def normalize_fragment_file(path: Path, list_key: str, cmap: dict[str, str]) -> bool:
    """Rewrite one MS fragment's component refs in place. Idempotent.

    Returns True when the file was rewritten. Malformed JSON is left for the
    validator to report rather than swallowed here.
    """
    if not path.is_file() or not cmap:
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    items = data.get(list_key)
    if not isinstance(items, list):
        return False
    changed = False
    for item in items:
        if not isinstance(item, dict):
            continue
        new_refs, item_changed = normalize_refs(item.get("affected_components"), cmap)
        if item_changed:
            item["affected_components"] = new_refs
            changed = True
    if changed:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return changed


def normalize_ms_fragments(fragments_dir: Path, components: Any) -> list[str]:
    """Normalise every known MS fragment under ``fragments_dir``.

    Returns the names of the files that were rewritten.
    """
    cmap = slug_to_cnn_map(components)
    if not cmap:
        return []
    return [
        name
        for name, list_key in MS_FRAGMENT_LIST_KEYS.items()
        if normalize_fragment_file(fragments_dir / name, list_key, cmap)
    ]
