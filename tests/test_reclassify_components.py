"""Regression tests for reclassify_components.py.

Focus: the resolver must never leave a threat tagged with a NON-REGISTERED
component id (a placeholder/phantom), because that dangles the §8/§6/§3
Component link at a missing anchor. Root cause of the 2026-06-13 juice-shop
dead `#backend-api` anchor: merge_threats._guess_component_from_path emits a
hardcoded "backend-api" placeholder and trusts reclassify to resolve it, but
reclassify bailed on a >=2-candidate glob ambiguity (routes/memory.ts matched
by both express-backend `routes/**` and file-upload-service exact
`routes/memory.ts`) and left the phantom in place.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import reclassify_components as rc  # noqa: E402

_COMPONENTS = [
    {"id": "angular-spa", "paths": ["frontend/src/**"]},
    {"id": "express-backend", "paths": ["server.ts", "routes/**", "lib/**", "models/**"]},
    {"id": "file-upload-service", "paths": ["routes/fileUpload.ts", "routes/memory.ts"]},
    {"id": "data-layer", "paths": ["data/**", "ftp/**"]},
]


def _run(threats):
    data = {"components": [dict(c) for c in _COMPONENTS], "threats": threats}
    out, changes = rc.reclassify(data)
    by = {t["id"]: (t.get("component") or t.get("component_id")) for t in out["threats"]}
    return out, by, changes


def test_phantom_ambiguous_resolves_to_most_specific_glob():
    # routes/memory.ts is matched by express-backend (routes/**) AND
    # file-upload-service (exact routes/memory.ts). The exact path wins.
    _out, by, changes = _run(
        [{"id": "T-002", "component": "backend-api", "evidence": {"file": "routes/memory.ts"}}]
    )
    assert by["T-002"] == "file-upload-service"
    assert ("T-002", "backend-api", "file-upload-service") in [
        (c["id"], c["from"], c["to"]) for c in changes
    ]


def test_phantom_single_match_resolves_cleanly():
    _out, by, _ = _run(
        [{"id": "T-001", "component": "backend-api", "evidence": {"file": "lib/insecurity.ts"}}]
    )
    assert by["T-001"] == "express-backend"


def test_pseudo_component_no_glob_match_falls_back_to_primary():
    # .github/* matches no component glob → primary application component.
    _out, by, _ = _run(
        [{"id": "T-005", "component": "ci-cd-pipeline", "evidence": {"file": ".github/workflows/ci.yml"}}]
    )
    assert by["T-005"] in {c["id"] for c in _COMPONENTS}


def test_real_component_spanning_boundary_is_preserved():
    # A threat legitimately assigned to a REAL component must NOT be moved just
    # because its evidence also matches another component's glob.
    _out, by, changes = _run(
        [{"id": "T-009", "component": "data-layer", "evidence": {"file": "data/static/users.yml"}}]
    )
    assert by["T-009"] == "data-layer"
    assert changes == []


def test_no_phantom_survives_postcondition():
    out, by, _ = _run(
        [
            {"id": "T-002", "component": "backend-api", "evidence": {"file": "routes/memory.ts"}},
            {"id": "T-001", "component": "backend-api", "evidence": {"file": "lib/insecurity.ts"}},
            {"id": "T-005", "component": "ci-cd-pipeline", "evidence": {"file": ".github/ci.yml"}},
        ]
    )
    known = {c["id"] for c in _COMPONENTS}
    for tid, comp in by.items():
        assert comp in known, f"{tid} still phantom: {comp}"
    assert rc.unresolved_phantoms(out) == []


def test_glob_specificity_exact_beats_broad():
    assert rc._glob_specificity("routes/memory.ts") > rc._glob_specificity("routes/**")
    assert rc._glob_specificity("server.ts") > rc._glob_specificity("**")


def test_unresolved_phantoms_reports_when_unresolvable():
    # A phantom whose evidence matches NO glob AND with no usable primary
    # (here: components have ids but the threat has no evidence file at all)
    # should be surfaced rather than silently shipped.
    data = {
        "components": [dict(c) for c in _COMPONENTS],
        "threats": [{"id": "T-099", "component": "ghost", "evidence": {}}],
    }
    out, _changes = rc.reclassify(data)
    leftovers = rc.unresolved_phantoms(out)
    assert ("T-099", "ghost") in leftovers
