"""_boundary_adjacency.py — single source of truth for "is this component
adjacent to this trust boundary?".

`covers_components` records the components a consolidation folded into the
surviving boundary (`prepare_trust_boundary_context._consolidate`). The
trust-boundaries schema is explicit that the field is "Treated as adjacent to
this boundary by dispatch, reference validation and ingress elevation" — but
only some consumers implemented that. These compared against `from`/`to`
alone and so treated a folded-in component as unrelated:

  * `scripts/validate_intermediate.py::_check_final_boundary_links`
  * `scripts/reclassify_components.py` (boundary-ref reconciliation)
  * `scripts/slice_cross_repo_for_component.py::_boundary_corpus`

The visible symptom was the 2026-07-31 juice-shop run: `_consolidate` folded
`external → realtime-channel` and `external → web3-nft` into
`external → backend-api`, so three findings whose `origin_component_id` named
a folded-in component failed final validation with "origin_component_id is
not adjacent to the referenced boundary", and `build_threat_model_yaml.py`
refused to rebuild the model. The reclassification path was worse: it dropped
such a reference silently instead of failing loudly.

One helper, imported by every consumer, so the invariant cannot drift again.
"""

from __future__ import annotations

from typing import Any


def is_adjacent(component_id: Any, boundary: Any) -> bool:
    """True when `component_id` is an endpoint of `boundary`, or was folded
    into it by a consolidation."""
    if not isinstance(component_id, str) or not component_id or not isinstance(boundary, dict):
        return False
    if component_id in {boundary.get("from"), boundary.get("to")}:
        return True
    covers = boundary.get("covers_components")
    return isinstance(covers, list) and component_id in covers
