#!/usr/bin/env python3
"""Single source of truth for the per-component STRIDE output glob.

`schemas/stride.schema.yaml` owns exactly one artifact shape:
`$OUTPUT_DIR/.stride-<component-id>.json`, one file per analyzed component,
written by `appsec-stride-analyzer` during the Phase-9 fan-out.

Three *other* artifacts squat the same `.stride-` prefix in the same
directory, all written BEFORE the fan-out and none of them a STRIDE result:

  * `.stride-dispatch-manifest.json`  (schemas/stride-dispatch-manifest.schema.yaml)
  * `.stride-selection.json`          (build_stride_dispatch_manifest.py sidecar)
  * `.stride-analyst-context.json`    (Analyst-A per-component context)

A bare `output_dir.glob(".stride-*.json")` therefore counts up to three
phantom "finished components" from the moment the manifest lands. That broke
real observability, not just cosmetics: the watchdog's Phase-9 canary fires on
`stride_count == 0`, so with a sidecar on disk it could never fire and a wedged
fan-out raised no alarm; `.merge-candidates.json` recorded component ids
`analyst-context` / `dispatch-manifest` / `selection` in its `source_files`
audit trail.

Every consumer that *reads or counts* per-component STRIDE output must go
through `stride_output_files()`. Cleanup paths deliberately keep the broad
glob — deleting the sidecars alongside the results on a full re-run is correct.

Adding a new `.stride-`-prefixed sidecar means adding it to
`RESERVED_SIDECARS` in the same change; `tests/test_stride_outputs.py`
guards both halves.
"""

from __future__ import annotations

from pathlib import Path

# Artifacts that share the `.stride-` prefix but are NOT per-component
# STRIDE results. Names, not patterns — a component id can never collide
# with a full filename match.
RESERVED_SIDECARS = frozenset(
    {
        ".stride-dispatch-manifest.json",
        ".stride-selection.json",
        ".stride-analyst-context.json",
    }
)

# The glob every consumer used to inline. Kept here so cleanup modules that
# legitimately want the broad pattern can name it instead of re-typing it.
STRIDE_GLOB = ".stride-*.json"


def is_stride_output(path: Path) -> bool:
    """True when `path` is a per-component `.stride-<component-id>.json`."""
    return path.name.startswith(".stride-") and path.name.endswith(".json") and path.name not in RESERVED_SIDECARS


def stride_output_files(output_dir: Path) -> list[Path]:
    """Sorted per-component STRIDE result files in `output_dir`, sidecars excluded."""
    return sorted(p for p in output_dir.glob(STRIDE_GLOB) if is_stride_output(p))


def component_id(path: Path) -> str:
    """`.stride-auth-service.json` → `auth-service`."""
    return path.name[len(".stride-") : -len(".json")]
