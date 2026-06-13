"""Regression tests for scripts/emit_general_mitigation_titles.py (2026-06-12).

Mitigation register/index titles must read as clear, general remediation
labels — not the detailed remediation instruction Stage-1 authored into
mitigation_title.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "emit_general_mitigation_titles.py"


def _load():
    spec = importlib.util.spec_from_file_location("emit_general_mitigation_titles", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["emit_general_mitigation_titles"] = mod
    spec.loader.exec_module(mod)
    return mod


egm = _load()


def _data(*mits, threats=None):
    return {"threats": threats or [], "mitigations": list(mits)}


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def test_cwe_maps_to_general_title():
    d = _data(
        {"id": "M-011", "title": "Replace raw SQL string interpolation with parameterized Sequelize ORM queries in login handler", "threat_ids": ["T-009"]},
        threats=[{"id": "T-009", "cwe": "CWE-89", "remediation": {"steps": ["x"]}}],
    )
    assert egm.apply(d) == 1
    assert d["mitigations"][0]["title"] == "Use parameterized database queries"


def test_explicit_cwe_fields_win_over_threat_lookup():
    d = _data(
        {"id": "M-011", "title": "Replace raw SQL string interpolation", "prevents_cwes": ["89"], "threat_ids": ["T-009"]},
        threats=[{"id": "T-009", "cwe": "CWE-601"}],
    )
    assert egm.apply(d) == 1
    assert d["mitigations"][0]["title"] == "Use parameterized database queries"


def test_addresses_can_resolve_cwe_from_threat_id_alias():
    d = _data(
        {"id": "M-012", "title": "Allow only local redirect targets", "addresses": ["T-010"]},
        threats=[{"t_id": "T-010", "cwe": "601"}],
    )
    assert egm.apply(d) == 1
    assert d["mitigations"][0]["title"] == "Validate redirect targets against an allowlist"


def test_cwe347_disambiguates_jwt_vs_signing():
    d = _data(
        {"id": "M-003", "title": "Pin algorithms allowlist in all expressJwt and jwt.verify calls to RS256", "threat_ids": ["T-001"]},
        {"id": "M-028", "title": "Add cosign signing step to release workflow; or use actions/attest-build-provenance", "threat_ids": ["T-028"]},
        threats=[{"id": "T-001", "cwe": "CWE-347"}, {"id": "T-028", "cwe": "CWE-347"}],
    )
    egm.apply(d)
    titles = {m["id"]: m["title"] for m in d["mitigations"]}
    assert titles["M-003"] == "Enforce JWT signature and algorithm verification"
    assert titles["M-028"] == "Sign and verify release artifacts"


def test_cwe400_disambiguates_eventloop_vs_parser():
    d = _data(
        {"id": "M-023", "title": "Add per-client rate limiting and move VM execution off the main event loop via worker threads", "threat_ids": ["T-023"]},
        {"id": "M-025", "title": "Replace yaml.load() with a safe YAML schema that limits alias/anchor expansion", "threat_ids": ["T-025"]},
        threats=[{"id": "T-023", "cwe": "CWE-400"}, {"id": "T-025", "cwe": "CWE-400"}],
    )
    egm.apply(d)
    titles = {m["id"]: m["title"] for m in d["mitigations"]}
    assert titles["M-023"] == "Offload CPU-bound work and bound execution time"
    assert titles["M-025"] == "Bound parser and decompression resource limits"


def test_detail_preserved_in_how_when_threat_has_no_remediation():
    """A mitigation whose threats carry no structured remediation must keep the
    original instruction in `how` so the §10 block still shows actionable detail."""
    d = _data(
        {"id": "M-029", "title": "Add HEALTHCHECK CMD curl -f http://localhost:3000/x", "threat_ids": ["T-027"]},
        threats=[{"id": "T-027", "cwe": "CWE-703", "remediation": None}],
    )
    egm.apply(d)
    m = d["mitigations"][0]
    assert m["title"] == "Add a container healthcheck"
    assert m["how"] == "Add HEALTHCHECK CMD curl -f http://localhost:3000/x"


def test_existing_detail_field_prevents_how_duplication():
    d = _data(
        {
            "id": "M-011",
            "title": "Replace raw SQL string interpolation with parameterized queries in routes/login.ts",
            "threat_ids": ["T-009"],
            "how": "Existing remediation body",
        },
        threats=[{"id": "T-009", "cwe": "CWE-89"}],
    )
    egm.apply(d)
    assert d["mitigations"][0]["title"] == "Use parameterized database queries"
    assert d["mitigations"][0]["how"] == "Existing remediation body"


def test_detail_not_duplicated_when_threat_has_steps():
    d = _data(
        {"id": "M-003", "title": "Pin algorithms allowlist …", "threat_ids": ["T-001"]},
        threats=[{"id": "T-001", "cwe": "CWE-347", "remediation": {"steps": ["a", "b"]}}],
    )
    egm.apply(d)
    assert "how" not in d["mitigations"][0] or not d["mitigations"][0].get("how")


def test_idempotent():
    d = _data(
        {"id": "M-007", "title": "Pin base image to @sha256:<digest>", "threat_ids": ["T-005"]},
        threats=[{"id": "T-005", "cwe": "CWE-1104"}],
    )
    assert egm.apply(d) == 1
    first = d["mitigations"][0]["title"]
    assert egm.apply(d) == 0  # second run is a no-op
    assert d["mitigations"][0]["title"] == first
    assert d["mitigations"][0]["_title_source"] == "Pin base image to @sha256:<digest>"


def test_skips_non_dict_and_empty_title_entries():
    d = _data(
        "not-a-mitigation",
        {"id": "M-001", "title": ""},
        {"id": "M-002", "title": "Already general"},
    )
    assert egm.apply(d) == 0
    assert d["mitigations"][2]["_title_source"] == "Already general"


def test_unmapped_cwe_falls_back_to_cleaner():
    d = _data(
        {"id": "M-099", "title": "Do the specific thing in routes/foo.ts:42", "threat_ids": ["T-099"]},
        threats=[{"id": "T-099", "cwe": "CWE-99999"}],
    )
    egm.apply(d)
    assert "routes/foo.ts:42" not in d["mitigations"][0]["title"]


def test_empty_title_fallback_is_empty():
    assert egm.generalize_title("", "") == ""
    assert egm._norm_cwe("") == ""


def test_main_writes_generalized_yaml(tmp_path, capsys):
    _write_yaml(
        tmp_path,
        _data(
            {"id": "M-011", "title": "Replace raw SQL string interpolation", "threat_ids": ["T-009"]},
            threats=[{"id": "T-009", "cwe": "CWE-89"}],
        ),
    )

    assert egm.main([str(tmp_path)]) == 0

    data = _read_yaml(tmp_path)
    assert data["mitigations"][0]["title"] == "Use parameterized database queries"
    assert "generalized 1 mitigation title" in capsys.readouterr().out


def test_main_report_only_prints_preview_without_writing(tmp_path, capsys):
    original = _data(
        {"id": "M-011", "title": "Replace raw SQL string interpolation", "threat_ids": ["T-009"]},
        "not-a-mitigation",
        threats=[{"id": "T-009", "cwe": "CWE-89"}],
    )
    _write_yaml(tmp_path, original)

    assert egm.main([str(tmp_path), "--report-only"]) == 0

    out = capsys.readouterr().out
    assert "M-011: [CWE-89]" in out
    assert "'Use parameterized database queries'" in out
    assert _read_yaml(tmp_path)["mitigations"][0]["title"] == "Replace raw SQL string interpolation"


def test_main_best_effort_noops_for_missing_and_unreadable_yaml(tmp_path, capsys):
    assert egm.main([str(tmp_path)]) == 0
    assert "no threat-model.yaml" in capsys.readouterr().err

    (tmp_path / "threat-model.yaml").write_text("threats: [\n", encoding="utf-8")
    assert egm.main([str(tmp_path)]) == 0
    assert "unreadable yaml" in capsys.readouterr().err
