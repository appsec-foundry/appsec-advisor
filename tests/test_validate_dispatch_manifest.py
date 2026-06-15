"""Unit tests for scripts/validate_dispatch_manifest.py.

The dispatch-manifest gate is exercised end-to-end by the pipeline, but its
branches (schema errors, missing index files, phantom components, coverage
warnings, CLI exit codes) were never directly unit-tested. These cases lock
in the gate contract.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "validate_dispatch_manifest.py"


@pytest.fixture(scope="module")
def vdm():
    spec = importlib.util.spec_from_file_location("validate_dispatch_manifest", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_dispatch_manifest"] = module
    spec.loader.exec_module(module)
    return module


def _minimal_component(**overrides):
    comp = {
        "component_id": "express-backend",
        "component_name": "Express Backend",
        "component_paths": ["routes/**"],
        "component_complexity": "moderate",
        "max_turns": 30,
        "index_paths": {
            "prior_findings": "none",
            "known_threats": "none",
            "cross_repo": "none",
            "requirements_violations": "none",
            "relevant_actors": "none",
        },
    }
    comp.update(overrides)
    return comp


def _minimal_manifest(**overrides):
    m = {"schema_version": 1, "components": [_minimal_component()]}
    m.update(overrides)
    return m


def _write_manifest(output_dir: Path, manifest: dict) -> Path:
    p = output_dir / ".stride-dispatch-manifest.json"
    p.write_text(json.dumps(manifest), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _resolve
# ---------------------------------------------------------------------------


class TestResolve:
    def test_relative_joins_output_dir(self, vdm, tmp_path):
        assert vdm._resolve(tmp_path, "sub/x.json") == tmp_path / "sub" / "x.json"

    def test_absolute_kept(self, vdm, tmp_path):
        abs_path = "/etc/hosts"
        assert vdm._resolve(tmp_path, abs_path) == Path(abs_path)


# ---------------------------------------------------------------------------
# _load_schema
# ---------------------------------------------------------------------------


def test_load_schema_returns_dict(vdm):
    schema = vdm._load_schema()
    assert isinstance(schema, dict)
    assert schema.get("type") == "object"


# ---------------------------------------------------------------------------
# validate() — happy and error paths
# ---------------------------------------------------------------------------


class TestValidate:
    def test_valid_manifest(self, vdm, tmp_path):
        mp = _write_manifest(tmp_path, _minimal_manifest())
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is True
        assert errors == []

    def test_manifest_not_found(self, vdm, tmp_path):
        ok, errors, warnings = vdm.validate(tmp_path / "nope.json", tmp_path)
        assert ok is False
        assert any("manifest not found" in e for e in errors)

    def test_manifest_invalid_json(self, vdm, tmp_path):
        mp = tmp_path / ".stride-dispatch-manifest.json"
        mp.write_text("{not valid json", encoding="utf-8")
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is False
        assert any("invalid JSON" in e for e in errors)

    def test_schema_violation_missing_required(self, vdm, tmp_path):
        # Drop the required schema_version key → structural schema error.
        bad = _minimal_manifest()
        del bad["schema_version"]
        mp = _write_manifest(tmp_path, bad)
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is False
        assert any("schema:" in e for e in errors)

    def test_schema_violation_bad_component_id(self, vdm, tmp_path):
        bad = _minimal_manifest(components=[_minimal_component(component_id="Bad ID!")])
        mp = _write_manifest(tmp_path, bad)
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is False
        assert any("schema:" in e for e in errors)

    def test_index_path_missing_file(self, vdm, tmp_path):
        comp = _minimal_component()
        comp["index_paths"]["prior_findings"] = "missing.json"
        mp = _write_manifest(tmp_path, _minimal_manifest(components=[comp]))
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is False
        assert any("index_paths.prior_findings points at a missing file" in e for e in errors)

    def test_index_path_existing_file_ok(self, vdm, tmp_path):
        existing = tmp_path / "prior.json"
        existing.write_text("[]", encoding="utf-8")
        comp = _minimal_component()
        comp["index_paths"]["prior_findings"] = "prior.json"
        mp = _write_manifest(tmp_path, _minimal_manifest(components=[comp]))
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is True
        assert errors == []

    def test_index_path_absolute_existing(self, vdm, tmp_path):
        existing = tmp_path / "abs.json"
        existing.write_text("[]", encoding="utf-8")
        comp = _minimal_component()
        comp["index_paths"]["cross_repo"] = str(existing)
        mp = _write_manifest(tmp_path, _minimal_manifest(components=[comp]))
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is True

    def test_phantom_component(self, vdm, tmp_path):
        # .components.json lists only 'angular-spa'; manifest references
        # 'express-backend' → phantom error.
        (tmp_path / ".components.json").write_text(
            json.dumps({"components": [{"id": "angular-spa"}]}), encoding="utf-8"
        )
        mp = _write_manifest(tmp_path, _minimal_manifest())
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is False
        assert any("phantom component not in .components.json: express-backend" in e for e in errors)

    def test_coverage_warning_for_missing_component(self, vdm, tmp_path):
        # .components.json has an extra component absent from the manifest →
        # non-fatal warning, manifest still valid.
        (tmp_path / ".components.json").write_text(
            json.dumps(
                {"components": [{"id": "express-backend"}, {"id": "angular-spa"}]}
            ),
            encoding="utf-8",
        )
        mp = _write_manifest(tmp_path, _minimal_manifest())
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is True
        assert any("angular-spa" in w and "absent from the manifest" in w for w in warnings)

    def test_components_json_as_bare_list(self, vdm, tmp_path):
        # .components.json can be a bare list (not a dict wrapper).
        (tmp_path / ".components.json").write_text(
            json.dumps([{"id": "express-backend"}]), encoding="utf-8"
        )
        mp = _write_manifest(tmp_path, _minimal_manifest())
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        assert ok is True
        assert errors == []

    def test_components_json_unreadable(self, vdm, tmp_path):
        (tmp_path / ".components.json").write_text("{bad json", encoding="utf-8")
        mp = _write_manifest(tmp_path, _minimal_manifest())
        ok, errors, warnings = vdm.validate(mp, tmp_path)
        # bad coverage file → warning, but manifest itself still valid
        assert ok is True
        assert any("could not read .components.json" in w for w in warnings)


# ---------------------------------------------------------------------------
# main() — CLI exit codes
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_valid_returns_0(self, vdm, tmp_path, capsys):
        mp = _write_manifest(tmp_path, _minimal_manifest())
        rc = vdm.main([str(mp), str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "OK: dispatch manifest valid" in out
        assert "1 component(s)" in out

    def test_main_invalid_returns_1(self, vdm, tmp_path, capsys):
        comp = _minimal_component()
        comp["index_paths"]["prior_findings"] = "missing.json"
        mp = _write_manifest(tmp_path, _minimal_manifest(components=[comp]))
        rc = vdm.main([str(mp), str(tmp_path)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "INVALID:" in err
        assert "ERROR" in err

    def test_main_emits_warnings(self, vdm, tmp_path, capsys):
        (tmp_path / ".components.json").write_text(
            json.dumps({"components": [{"id": "express-backend"}, {"id": "extra"}]}),
            encoding="utf-8",
        )
        mp = _write_manifest(tmp_path, _minimal_manifest())
        rc = vdm.main([str(mp), str(tmp_path)])
        assert rc == 0
        err = capsys.readouterr().err
        assert "WARN" in err

    def test_main_schema_missing_returns_2(self, vdm, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(vdm, "SCHEMA_PATH", tmp_path / "no-schema.yaml")
        mp = _write_manifest(tmp_path, _minimal_manifest())
        rc = vdm.main([str(mp), str(tmp_path)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "FATAL: schema missing" in err


# ---------------------------------------------------------------------------
# End-to-end via subprocess (covers __main__ dispatch + real schema load)
# ---------------------------------------------------------------------------


class TestSubprocess:
    def test_cli_valid(self, run_plugin_script, tmp_path):
        _write_manifest(tmp_path, _minimal_manifest())
        result = run_plugin_script(
            "validate_dispatch_manifest.py",
            str(tmp_path / ".stride-dispatch-manifest.json"),
            str(tmp_path),
            check=False,
        )
        assert result.returncode == 0
        assert "OK: dispatch manifest valid" in result.stdout

    def test_cli_invalid(self, run_plugin_script, tmp_path):
        bad = _minimal_manifest()
        del bad["schema_version"]
        _write_manifest(tmp_path, bad)
        result = run_plugin_script(
            "validate_dispatch_manifest.py",
            str(tmp_path / ".stride-dispatch-manifest.json"),
            str(tmp_path),
            check=False,
        )
        assert result.returncode == 1
