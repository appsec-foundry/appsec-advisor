"""Consistency tests between the renderer's heuristics and the committed
taxonomies in data/.

These tests catch the common "add a keyword to the renderer, forget to add
the corresponding TH entry" regression — and vice versa.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"
CAT_TAX = REPO_ROOT / "data" / "threat-category-taxonomy.yaml"
VEK_TAX = REPO_ROOT / "data" / "breach-vector-taxonomy.yaml"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPT_PATH)


@pytest.fixture(scope="module")
def category_taxonomy() -> dict[str, dict]:
    data = yaml.safe_load(CAT_TAX.read_text(encoding="utf-8"))
    return {c["id"]: c for c in (data.get("categories") or []) if "id" in c}


@pytest.fixture(scope="module")
def vektor_taxonomy() -> dict[str, dict]:
    data = yaml.safe_load(VEK_TAX.read_text(encoding="utf-8"))
    entries = data.get("vectors") or data.get("vektors") or []
    return {v["id"]: v for v in entries if "id" in v}


# ---------------------------------------------------------------------------
# threat-category-taxonomy.yaml ↔ renderer's _CATEGORY_KEYWORD_MAP
# ---------------------------------------------------------------------------


def test_every_keyword_map_target_exists_in_taxonomy(category_taxonomy):
    """Every TH-NN target referenced by the renderer's keyword heuristic must
    exist in threat-category-taxonomy.yaml, otherwise rendered anchors will
    not resolve to a category description."""
    missing = []
    for keys, cat in compose._CATEGORY_KEYWORD_MAP:
        if cat not in category_taxonomy:
            missing.append(f"{cat} (trigger keys: {keys[:2]})")
    # TH-00 is allowed as a sentinel fallback; everything else must exist.
    missing = [m for m in missing if not m.startswith("TH-00")]
    assert not missing, f"Renderer keyword-map targets missing from taxonomy: {missing}"


def test_every_stride_fallback_target_exists_in_taxonomy(category_taxonomy):
    missing = [cat for cat in compose._STRIDE_TO_TH_FALLBACK.values() if cat not in category_taxonomy]
    assert not missing, f"STRIDE→TH fallback targets missing from taxonomy: {missing}"


def test_stride_fallback_covers_all_stride_verbs():
    """All six canonical STRIDE verbs must have a fallback."""
    stride_verbs = {
        "tampering",
        "spoofing",
        "repudiation",
        "information disclosure",
        "denial of service",
        "elevation of privilege",
    }
    covered = set(compose._STRIDE_TO_TH_FALLBACK.keys())
    missing = stride_verbs - covered
    assert not missing, f"STRIDE verbs without TH fallback: {missing}"


def test_category_taxonomy_has_required_fields(category_taxonomy):
    """Every TH-NN entry must carry title, description, cwe_pillar and
    owasp_top10_2025 — these back the §8.A summary table columns."""
    bad = []
    for cid, c in category_taxonomy.items():
        for field in ("title", "description", "cwe_pillar", "owasp_top10_2025"):
            if not c.get(field):
                bad.append(f"{cid}.{field} missing")
    assert not bad, "\n".join(bad)


# ---------------------------------------------------------------------------
# breach-vector-taxonomy.yaml — renderer references
# ---------------------------------------------------------------------------


def test_vektor_taxonomy_has_required_entries(vektor_taxonomy):
    """The reference threat model uses these vektor IDs in Top Findings —
    every one must exist in the taxonomy, otherwise link cells break."""
    needed = {
        "internet-anon",
        "internet-user",
        "internet-priv-user",
        "victim-required",
        "build-time",
        "repo-read",
        "n-a",
    }
    missing = needed - set(vektor_taxonomy.keys())
    assert not missing, f"breach-vector-taxonomy missing canonical entries: {missing}"


def test_every_vektor_has_label_and_breach_distance(vektor_taxonomy):
    bad = []
    for vid, v in vektor_taxonomy.items():
        if not v.get("label"):
            bad.append(f"{vid}: missing label")
        bd = v.get("breach_distance")
        if bd is not None and bd not in (1, 2, 3):
            bad.append(f"{vid}: breach_distance {bd!r} not in {{1,2,3}}")
    assert not bad, "\n".join(bad)
