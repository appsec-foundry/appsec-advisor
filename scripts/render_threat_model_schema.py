#!/usr/bin/env python3
"""
render_threat_model_schema.py — fragment IDs for the LEGACY marker-substitution renderer.

LEGACY MODULE — used only by render_threat_model.py (legacy renderer) and
tests/test_render_threat_model.py. The current production renderer is
compose_threat_model.py, which is driven by data/sections-contract.yaml and
does not use this module.

The constants below reflect the transitional "Step 1 passthrough" state of the
old migration and are intentionally NOT updated to reflect the current
sections-contract — they exist only to keep the legacy renderer and its tests
in lockstep.
"""

from __future__ import annotations


REQUIRED_FRAGMENTS: list[str] = [
    # Step 1 — MVP passthrough fragment, will be removed in later steps
    "99-full-body.md",
]

OPTIONAL_FRAGMENTS: list[str] = [
    "00b-changelog.md",
    "07b-requirements-compliance.md",
]

# Fragments the resolver produces itself (not written by agents).
GENERATED_FRAGMENTS: list[str] = [
    "00-toc.md",
]
