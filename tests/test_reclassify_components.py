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

import json
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
    _out, by, changes = _run([{"id": "T-002", "component": "backend-api", "evidence": {"file": "routes/memory.ts"}}])
    assert by["T-002"] == "file-upload-service"
    assert ("T-002", "backend-api", "file-upload-service") in [(c["id"], c["from"], c["to"]) for c in changes]


def test_phantom_single_match_resolves_cleanly():
    _out, by, _ = _run([{"id": "T-001", "component": "backend-api", "evidence": {"file": "lib/insecurity.ts"}}])
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


# ---------------------------------------------------------------------------
# Pure-helper coverage
# ---------------------------------------------------------------------------


def test_glob_to_regex_wildcards_and_specials():
    assert rc._glob_to_regex("routes/*.ts").search("routes/a.ts")
    assert not rc._glob_to_regex("routes/*.ts").search("routes/sub/a.ts")
    assert rc._glob_to_regex("routes/**").search("routes/sub/deep.ts")
    assert rc._glob_to_regex("file?.ts").search("file1.ts")
    # special-char escaping: a literal dot only matches a dot
    pat = rc._glob_to_regex("a.b")
    assert pat.search("a.b")
    assert not pat.search("axb")


def test_build_matcher_anon_and_non_str_paths():
    cid, pats = rc._build_matcher({"paths": ["x/**", 5, "", "  "]})
    assert cid == "<anon>"
    # only the one valid string glob produces a pattern
    assert len(pats) == 1


def test_evidence_files_list_form():
    threat = {
        "evidence": [
            {"file": "routes/a.ts"},
            {"file": "  "},
            {"file": "lib/b.ts"},
            "not-a-dict",
        ]
    }
    assert rc._evidence_files(threat) == ["routes/a.ts", "lib/b.ts"]


def test_evidence_files_none():
    assert rc._evidence_files({"evidence": None}) == []
    assert rc._evidence_files({}) == []


def test_sort_tid_malformed():
    assert rc._sort_tid("T-3") == (3, "T-3")
    assert rc._sort_tid("garbage")[0] == 10**9


def test_primary_component_id_falls_back_to_first():
    comps = [{"id": "alpha", "paths": ["x/**"]}, {"id": "beta", "paths": ["y/**"]}]
    assert rc._primary_component_id(comps) == "alpha"


def test_primary_component_id_prefers_entrypoint():
    comps = [
        {"id": "alpha", "paths": ["x/**"]},
        {"id": "beta", "paths": ["server.ts", "routes/**"]},
    ]
    assert rc._primary_component_id(comps) == "beta"


# ---------------------------------------------------------------------------
# reclassify — early-return guards
# ---------------------------------------------------------------------------


def test_reclassify_no_components():
    data = {"threats": []}
    out, changes = rc.reclassify(data)
    assert changes == []
    assert out is data


def test_reclassify_components_without_paths():
    data = {"components": [{"id": "x"}], "threats": []}
    _out, changes = rc.reclassify(data)
    assert changes == []


def test_reclassify_threats_not_list():
    data = {"components": [dict(c) for c in _COMPONENTS], "threats": "nope"}
    _out, changes = rc.reclassify(data)
    assert changes == []


def test_reclassify_threat_already_correct_no_change():
    _out, by, changes = _run([{"id": "T-010", "component": "express-backend", "evidence": {"file": "routes/x.ts"}}])
    assert by["T-010"] == "express-backend"
    assert changes == []


def test_reclassify_threat_without_evidence_skipped():
    _out, _by, changes = _run([{"id": "T-011", "component": "express-backend"}])
    assert changes == []


def test_reclassify_syncs_threat_ids_lists():
    # A PHANTOM (non-registered) current component with a single glob match
    # gets reassigned, and the per-component threat_ids lists are kept in sync.
    components = [
        {"id": "express-backend", "paths": ["routes/**"], "threat_ids": []},
        {"id": "data-layer", "paths": ["data/**"], "threat_ids": ["T-020"]},
    ]
    data = {
        "components": components,
        "threats": [{"id": "T-020", "component": "phantom-api", "evidence": {"file": "routes/x.ts"}}],
    }
    out, changes = rc.reclassify(data)
    assert changes
    by = {c["id"]: c for c in out["components"]}
    # T-020 moves to express-backend; sync adds it there.
    assert "T-020" in by["express-backend"]["threat_ids"]


def test_sync_component_threat_ids_creates_list_when_absent():
    components = [
        {"id": "old", "threat_ids": ["T-1"]},
        {"id": "new"},  # no threat_ids key
    ]
    rc._sync_component_threat_ids(components, [{"id": "T-1", "from": "old", "to": "new"}])
    by = {c["id"]: c for c in components}
    assert "T-1" not in by["old"]["threat_ids"]
    assert by["new"]["threat_ids"] == ["T-1"]


# ---------------------------------------------------------------------------
# _sync_threats_merged
# ---------------------------------------------------------------------------


def test_sync_threats_merged_no_changes(tmp_path):
    assert rc._sync_threats_merged(tmp_path, []) == 0


def test_sync_threats_merged_no_file(tmp_path):
    assert rc._sync_threats_merged(tmp_path, [{"id": "T-1", "from": "a", "to": "b"}]) == 0


def test_sync_threats_merged_uses_t_id(tmp_path):
    merged = {
        "threats": [
            {"id": "F-001", "t_id": "T-002", "component_id": "backend-api", "component": "backend-api"},
            {"id": "F-002", "t_id": "T-999", "component_id": "other"},
        ]
    }
    (tmp_path / ".threats-merged.json").write_text(json.dumps(merged), encoding="utf-8")
    n = rc._sync_threats_merged(tmp_path, [{"id": "T-002", "from": "backend-api", "to": "file-upload-service"}])
    assert n == 1
    updated = json.loads((tmp_path / ".threats-merged.json").read_text())
    assert updated["threats"][0]["component_id"] == "file-upload-service"
    assert updated["threats"][0]["component"] == "file-upload-service"
    # untouched
    assert updated["threats"][1]["component_id"] == "other"


def test_sync_threats_merged_falls_back_to_id(tmp_path):
    # No t_id → lookup falls back to the `id` field (old merged schema).
    merged = {"threats": [{"id": "T-002", "component_id": "backend-api"}]}
    (tmp_path / ".threats-merged.json").write_text(json.dumps(merged), encoding="utf-8")
    n = rc._sync_threats_merged(tmp_path, [{"id": "T-002", "from": "backend-api", "to": "express-backend"}])
    assert n == 1


def test_sync_threats_merged_bad_json(tmp_path):
    (tmp_path / ".threats-merged.json").write_text("{bad json", encoding="utf-8")
    assert rc._sync_threats_merged(tmp_path, [{"id": "T-1", "from": "a", "to": "b"}]) == 0


def test_sync_threats_merged_threats_not_list(tmp_path):
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": "x"}), encoding="utf-8")
    assert rc._sync_threats_merged(tmp_path, [{"id": "T-1", "from": "a", "to": "b"}]) == 0


def test_sync_threats_merged_skips_non_dict_and_unmatched(tmp_path):
    merged = {"threats": ["notdict", {"t_id": "T-X"}]}
    (tmp_path / ".threats-merged.json").write_text(json.dumps(merged), encoding="utf-8")
    assert rc._sync_threats_merged(tmp_path, [{"id": "T-002", "from": "a", "to": "b"}]) == 0


# ---------------------------------------------------------------------------
# main() — CLI
# ---------------------------------------------------------------------------


def _write_yaml(path, data):
    import yaml as _yaml

    path.write_text(_yaml.safe_dump(data), encoding="utf-8")


def test_main_bad_args(capsys):
    assert rc.main([]) == 2
    assert "Usage:" in capsys.readouterr().err


def test_main_no_yaml(tmp_path, capsys):
    assert rc.main([str(tmp_path)]) == 1
    assert "no yaml" in capsys.readouterr().err


def test_main_unparseable_yaml(tmp_path, capsys):
    (tmp_path / "threat-model.yaml").write_text("a: [unterminated\n", encoding="utf-8")
    assert rc.main([str(tmp_path)]) == 1
    assert "could not parse" in capsys.readouterr().err


def test_main_yaml_not_mapping(tmp_path, capsys):
    (tmp_path / "threat-model.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert rc.main([str(tmp_path)]) == 1
    assert "did not parse to a mapping" in capsys.readouterr().err


def test_main_no_changes(tmp_path, capsys):
    data = {
        "components": [dict(c) for c in _COMPONENTS],
        "threats": [{"id": "T-001", "component": "express-backend", "evidence": {"file": "routes/x.ts"}}],
    }
    _write_yaml(tmp_path / "threat-model.yaml", data)
    assert rc.main([str(tmp_path)]) == 0
    assert "nothing to reassign" in capsys.readouterr().out


def test_main_reassigns_and_writes(tmp_path, capsys):
    data = {
        "components": [dict(c) for c in _COMPONENTS],
        "threats": [{"id": "T-002", "component": "backend-api", "evidence": {"file": "routes/memory.ts"}}],
    }
    _write_yaml(tmp_path / "threat-model.yaml", data)
    merged = {"threats": [{"id": "F-1", "t_id": "T-002", "component_id": "backend-api"}]}
    (tmp_path / ".threats-merged.json").write_text(json.dumps(merged), encoding="utf-8")

    assert rc.main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "reassigned 1 threat" in out

    import yaml as _yaml

    reloaded = _yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    by = {t["id"]: t["component"] for t in reloaded["threats"]}
    assert by["T-002"] == "file-upload-service"


def test_main_reassigns_many_truncates_details(tmp_path, capsys):
    # >8 changes triggers the "(+N more)" branch.
    comps = [dict(c) for c in _COMPONENTS]
    threats = [
        {"id": f"T-{i:03d}", "component": "backend-api", "evidence": {"file": "lib/insecurity.ts"}} for i in range(10)
    ]
    data = {"components": comps, "threats": threats}
    _write_yaml(tmp_path / "threat-model.yaml", data)
    assert rc.main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "more)" in out


def test_main_warns_on_leftover_phantom(tmp_path, capsys):
    # A threat whose component is a phantom AND evidence matches no glob and
    # cannot be resolved (no primary entrypoint helps but file matches nothing)
    # — force leftover by giving evidence that matches nothing and a phantom
    # that is also the primary fallback would resolve; instead use a threat
    # with no evidence file so it is skipped and remains phantom.
    data = {
        "components": [dict(c) for c in _COMPONENTS],
        "threats": [
            {"id": "T-001", "component": "backend-api", "evidence": {"file": "lib/insecurity.ts"}},
            {"id": "T-099", "component": "ghost", "evidence": {}},
        ],
    }
    _write_yaml(tmp_path / "threat-model.yaml", data)
    assert rc.main([str(tmp_path)]) == 0
    err = capsys.readouterr().err
    assert "still carry a" in err and "T-099" in err


def test_main_cli_subprocess(run_plugin_script, tmp_path):
    import yaml as _yaml

    data = {
        "components": [dict(c) for c in _COMPONENTS],
        "threats": [{"id": "T-001", "component": "express-backend", "evidence": {"file": "routes/x.ts"}}],
    }
    (tmp_path / "threat-model.yaml").write_text(_yaml.safe_dump(data), encoding="utf-8")
    result = run_plugin_script("reclassify_components.py", str(tmp_path), check=False)
    assert result.returncode == 0
    assert "reclassify_components:" in result.stdout
