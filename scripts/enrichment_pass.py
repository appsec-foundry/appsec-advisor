#!/usr/bin/env python3
"""Bind emitter completion to the canonical YAML data, excluding its own receipt.

Only the completed emitter pass creates a receipt. Later canonical writers may
continue a receipt they verified before mutation; they cannot repair an absent
or stale receipt. Rebuilds deliberately discard it with the old meta block.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
from datetime import datetime, timezone

import yaml
from _atomic_io import atomic_write_text
from _path_guard import is_safe_to_read, run_path_arg


def model_hash(document: dict) -> str:
    """Hash model data independently of presentation and the receipt itself."""
    payload = copy.deepcopy(document)
    meta = payload.get("meta")
    if isinstance(meta, dict):
        meta.pop("enrichment_pass", None)
    canonical = yaml.safe_dump(payload, sort_keys=True, allow_unicode=True, width=120)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def valid_receipt(document: dict) -> bool:
    """Reject missing, malformed, or stale completion receipts."""
    meta = document.get("meta")
    receipt = meta.get("enrichment_pass") if isinstance(meta, dict) else None
    if not isinstance(receipt, dict) or set(receipt) != {"completed_at", "yaml_sha256"}:
        return False
    timestamp = receipt.get("completed_at")
    digest = receipt.get("yaml_sha256")
    if not isinstance(timestamp, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False
    try:
        if datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is None:
            return False
    except ValueError:
        return False
    return digest == model_hash(document)


def stamp(document: dict) -> None:
    """Record a completed emitter pass; never called by subsequent writers."""
    meta = document.setdefault("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("model meta must be a mapping")
    meta["enrichment_pass"] = {
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "yaml_sha256": model_hash(document),
    }


class EnrichmentContinuation:
    """Capture validity before mutation and carry only that receipt forward."""

    def __init__(self, document: dict) -> None:
        self.receipt = copy.deepcopy(document["meta"]["enrichment_pass"]) if valid_receipt(document) else None

    def refresh(self, document: dict) -> None:
        """Preserve the completion time without healing missing or stale input."""
        meta = document.get("meta")
        if self.receipt is not None and isinstance(meta, dict) and meta.get("enrichment_pass") == self.receipt:
            meta["enrichment_pass"] = {**self.receipt, "yaml_sha256": model_hash(document)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=run_path_arg)
    args = parser.parse_args()
    path = args.output_dir / "threat-model.yaml"
    if not is_safe_to_read(path, args.output_dir):
        parser.error("threat-model.yaml must be a regular file contained in output_dir")
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            parser.error("threat-model.yaml must be a mapping")
        stamp(document)
        atomic_write_text(path, yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=120))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
