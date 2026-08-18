#!/usr/bin/env python3
"""
_artifact_stamp.py — keep a run artifact's timestamp still while its content is.

A context-v2 boundary may be invoked a second time: `orchestration-actions.md`
says a re-invocation repeats the dispatch it already issued, and only a
*changed* action under the same job identity is rejected as a replay. A
boundary that regenerates an artifact and then receipts it into that action can
only repeat itself while the artifact's bytes stand still. A wall-clock
`generated_at` alone breaks that: the receipt hash moves,
`context_routing.action_already_issued` sees different content for the same job,
and the run ends at an authoritative abort with every analyzer result already
on disk.

Producers bound by this rule, because a boundary rebuilds their output before
receipting it:

  - `.stride-dispatch-manifest.json` — `build_stride_dispatch_manifest`, whose
    stamp also feeds the component context-plan hash and the wave-plan
    fingerprint
  - `.merge-candidates.json` — `merge_threats collect`, receipted through the
    merge-review projection at `context-v2-post-stride`
  - `.threats-merged.json` — `merge_threats finalize`, receipted directly at the
    triage repair dispatch and by hash inside the evidence and synthesis
    projections

A producer whose output a boundary only reads does not need this: nothing
rewrites it between two calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def carry_generated_at(path: Path, payload: dict[str, Any], *, field: str = "generated_at") -> dict[str, Any]:
    """Keep the prior timestamp when everything else in `payload` is unchanged.

    `path` is where `payload` is about to be written. A missing, unreadable, or
    differing prior artifact leaves the fresh timestamp in place, so content
    that really changed still carries the time it was produced.
    """
    try:
        prior = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return payload
    if not isinstance(prior, dict) or not isinstance(prior.get(field), str):
        return payload
    if {k: v for k, v in prior.items() if k != field} != {k: v for k, v in payload.items() if k != field}:
        return payload
    payload[field] = prior[field]
    return payload
