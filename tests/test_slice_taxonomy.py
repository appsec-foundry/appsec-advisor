"""Unit tests for scripts/slice_taxonomy.py.

Covers profile detection, the per-taxonomy slicing helpers, data-dir discovery,
YAML load/write round-tripping, and the CLI (main) for both passthrough and
profile-matched component types.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import slice_taxonomy as st
import yaml


# ---------------------------------------------------------------------------
# detect_profile
# ---------------------------------------------------------------------------
class TestDetectProfile:
    def test_frontend_keyword_matches(self):
        p = st.detect_profile("frontend", "web-spa")
        assert p is not None
        assert p["name"] == "frontend"

    def test_auth_matches_via_component_id(self):
        # type unknown, id carries the keyword
        p = st.detect_profile("xyz", "login-service")
        assert p is not None
        assert p["name"] == "auth"

    def test_unknown_returns_none(self):
        assert st.detect_profile("totally-unknown-thing", "qqq") is None

    def test_special_chars_normalised(self):
        # punctuation outside [a-z0-9 _-] is stripped to spaces; the hyphenated
        # "ci-cd" keyword survives because '-' is preserved.
        p = st.detect_profile("CI-CD!!", "")
        assert p is not None
        assert p["name"] == "ci-cd"

    def test_punctuation_breaking_keyword_no_match(self):
        # '/' is replaced by a space, splitting "ci/cd" so the "ci-cd" keyword
        # no longer matches → passthrough (None).
        assert st.detect_profile("CI/CD", "") is None

    def test_first_match_wins(self):
        # "backend" precedes "database" in profile order; needle has both
        p = st.detect_profile("backend service", "postgres-db")
        assert p["name"] == "backend-api"


# ---------------------------------------------------------------------------
# slice_threat_categories
# ---------------------------------------------------------------------------
class TestSliceThreatCategories:
    def test_keeps_only_wanted_categories(self):
        data = {
            "categories": [{"id": "TH-01"}, {"id": "TH-02"}, {"id": "TH-99"}],
            "cwe_to_th": {
                "CWE-89": ["TH-01"],
                "CWE-79": ["TH-02", "TH-99"],
                "CWE-1": ["TH-99"],
            },
        }
        out = st.slice_threat_categories(data, {"TH-01", "TH-02"})
        ids = {c["id"] for c in out["categories"]}
        assert ids == {"TH-01", "TH-02"}
        # CWE-1 maps only to TH-99 → dropped entirely
        assert "CWE-1" not in out["cwe_to_th"]
        # CWE-79 retained but TH-99 filtered out of its list
        assert out["cwe_to_th"]["CWE-79"] == ["TH-02"]

    def test_does_not_mutate_input(self):
        data = {"categories": [{"id": "TH-01"}, {"id": "TH-02"}]}
        st.slice_threat_categories(data, {"TH-01"})
        assert len(data["categories"]) == 2

    def test_missing_keys_tolerated(self):
        out = st.slice_threat_categories({}, {"TH-01"})
        assert out["categories"] == []
        assert "cwe_to_th" not in out


# ---------------------------------------------------------------------------
# slice_cwe_taxonomy
# ---------------------------------------------------------------------------
class TestSliceCweTaxonomy:
    def test_keeps_only_listed_cwes(self):
        data = {"cwes": {"CWE-89": {"x": 1}, "CWE-79": {"x": 2}, "CWE-22": {"x": 3}}}
        out = st.slice_cwe_taxonomy(data, {"CWE-89", "CWE-22"})
        assert set(out["cwes"]) == {"CWE-89", "CWE-22"}

    def test_no_cwes_key(self):
        out = st.slice_cwe_taxonomy({"other": 1}, {"CWE-89"})
        assert out == {"other": 1}


# ---------------------------------------------------------------------------
# slice_controls
# ---------------------------------------------------------------------------
class TestSliceControls:
    def test_passthrough_copy(self):
        data = {"controls": [1, 2, 3]}
        out = st.slice_controls(data, {"TH-01"})
        assert out == data
        assert out is not data  # deep copy


# ---------------------------------------------------------------------------
# slice_compound_chains
# ---------------------------------------------------------------------------
class TestSliceCompoundChains:
    def test_keeps_chains_with_in_scope_th(self):
        data = {
            "chain_patterns": [
                {"th_ids": ["TH-01"]},
                {"th_ids": ["TH-99"]},
                {"categories": ["TH-02"]},
                {},  # no th info → kept
            ]
        }
        out = st.slice_compound_chains(data, {"TH-01", "TH-02"})
        kept = out["chain_patterns"]
        assert {"th_ids": ["TH-01"]} in kept
        assert {"categories": ["TH-02"]} in kept
        assert {} in kept
        assert {"th_ids": ["TH-99"]} not in kept

    def test_no_chains_key_returns_copy(self):
        data = {"foo": 1}
        out = st.slice_compound_chains(data, {"TH-01"})
        assert out == data
        assert out is not data


# ---------------------------------------------------------------------------
# find_data_dir
# ---------------------------------------------------------------------------
class TestFindDataDir:
    def test_explicit_returned_unchanged(self):
        assert st.find_data_dir("/some/explicit") == "/some/explicit"

    def test_autodetect_finds_real_data(self):
        # The repo has a data/ dir within 4 hops of scripts/.
        d = st.find_data_dir(None)
        assert Path(d).is_dir()
        assert Path(d).name == "data"

    def test_missing_raises(self, monkeypatch, tmp_path):
        # Point __file__ at an isolated location with no data/ ancestor.
        fake = tmp_path / "a" / "b" / "c" / "d" / "scripts" / "slice_taxonomy.py"
        fake.parent.mkdir(parents=True)
        monkeypatch.setattr(st.os.path, "abspath", lambda _p: str(fake))
        with pytest.raises(FileNotFoundError):
            st.find_data_dir(None)


# ---------------------------------------------------------------------------
# load_yaml / write_yaml round trip
# ---------------------------------------------------------------------------
class TestYamlIO:
    def test_write_then_load(self, tmp_path):
        dst = tmp_path / "nested" / "out.yaml"
        payload = {"categories": [{"id": "TH-01"}], "k": "ü"}
        st.write_yaml(payload, str(dst))
        assert dst.is_file()
        loaded = st.load_yaml(str(dst))
        assert loaded == payload

    def test_load_non_dict_returns_empty(self, tmp_path):
        p = tmp_path / "list.yaml"
        p.write_text("- a\n- b\n")
        assert st.load_yaml(str(p)) == {}


# ---------------------------------------------------------------------------
# main() via direct call (covers the slicing dispatch)
# ---------------------------------------------------------------------------
def _seed_data_dir(root: Path) -> Path:
    d = root / "data"
    d.mkdir()
    (d / "threat-category-taxonomy.yaml").write_text(
        yaml.dump(
            {
                "categories": [{"id": "TH-01"}, {"id": "TH-79", "n": 1}, {"id": "TH-99"}],
                "cwe_to_th": {"CWE-89": ["TH-01"], "CWE-zzz": ["TH-99"]},
            }
        )
    )
    (d / "cwe-taxonomy.yaml").write_text(
        yaml.dump({"cwes": {"CWE-89": {}, "CWE-zzz": {}, "CWE-79": {}}})
    )
    (d / "architectural-controls.yaml").write_text(yaml.dump({"controls": [1, 2]}))
    (d / "compound-chain-patterns.yaml").write_text(
        yaml.dump({"chain_patterns": [{"th_ids": ["TH-01"]}, {"th_ids": ["TH-99"]}]})
    )
    return d


class TestMainDirect:
    def _run(self, monkeypatch, argv):
        monkeypatch.setattr(st.sys, "argv", ["slice_taxonomy.py", *argv])
        return st.main()

    def test_profile_match_writes_slices(self, monkeypatch, tmp_path, capsys):
        data_dir = _seed_data_dir(tmp_path)
        out_dir = tmp_path / "out"
        rc = self._run(
            monkeypatch,
            ["backend-api", str(out_dir), "--component-id", "api", "--data-dir", str(data_dir)],
        )
        assert rc == 0
        slice_dir = out_dir / ".taxonomy-slices" / "api"
        assert (slice_dir / "threat-category-taxonomy.yaml").is_file()
        # backend-api includes TH-01 → CWE-89 kept; CWE-zzz (TH-99) dropped
        cwe = yaml.safe_load((slice_dir / "cwe-taxonomy.yaml").read_text())
        assert "CWE-89" in cwe["cwes"]
        assert "CWE-zzz" not in cwe["cwes"]
        # extra_cwes for backend-api include CWE-89 already; CWE-79 not in profile
        assert "CWE-79" not in cwe["cwes"]
        out = capsys.readouterr().out
        assert "backend-api profile" in out

    def test_passthrough_unknown_type_exit_1(self, monkeypatch, tmp_path, capsys):
        data_dir = _seed_data_dir(tmp_path)
        out_dir = tmp_path / "out2"
        rc = self._run(
            monkeypatch,
            ["weird-unknown", str(out_dir), "--data-dir", str(data_dir)],
        )
        assert rc == 1
        slice_dir = out_dir / ".taxonomy-slices" / "weird-unknown"
        # passthrough copies everything unchanged
        cwe = yaml.safe_load((slice_dir / "cwe-taxonomy.yaml").read_text())
        assert set(cwe["cwes"]) == {"CWE-89", "CWE-zzz", "CWE-79"}
        assert "passthrough" in capsys.readouterr().out

    def test_component_id_derived_from_type(self, monkeypatch, tmp_path):
        data_dir = _seed_data_dir(tmp_path)
        out_dir = tmp_path / "out3"
        rc = self._run(monkeypatch, ["Frontend SPA", str(out_dir), "--data-dir", str(data_dir)])
        # "frontend" keyword matches; component_id derived by slugifying the type
        assert rc == 0
        assert (out_dir / ".taxonomy-slices" / "frontend-spa").is_dir()

    def test_taxonomies_subset(self, monkeypatch, tmp_path):
        data_dir = _seed_data_dir(tmp_path)
        out_dir = tmp_path / "out4"
        rc = self._run(
            monkeypatch,
            ["auth", str(out_dir), "--data-dir", str(data_dir), "--taxonomies", "cwe"],
        )
        assert rc == 0
        slice_dir = out_dir / ".taxonomy-slices" / "auth"
        assert (slice_dir / "cwe-taxonomy.yaml").is_file()
        # threats not requested → not written
        assert not (slice_dir / "threat-category-taxonomy.yaml").exists()

    def test_missing_source_file_skipped(self, monkeypatch, tmp_path, capsys):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        # only provide threats file; others missing
        (data_dir / "threat-category-taxonomy.yaml").write_text(
            yaml.dump({"categories": [{"id": "TH-01"}], "cwe_to_th": {}})
        )
        out_dir = tmp_path / "out5"
        rc = self._run(monkeypatch, ["auth", str(out_dir), "--data-dir", str(data_dir)])
        assert rc == 0
        err = capsys.readouterr().err
        assert "not found" in err

    def test_write_error_returns_2(self, monkeypatch, tmp_path, capsys):
        data_dir = _seed_data_dir(tmp_path)
        out_dir = tmp_path / "out6"

        def boom(_data, _path):
            raise OSError("disk full")

        monkeypatch.setattr(st, "write_yaml", boom)
        rc = self._run(monkeypatch, ["auth", str(out_dir), "--data-dir", str(data_dir)])
        assert rc == 2
        assert "ERROR writing" in capsys.readouterr().err

    def test_bad_data_dir_returns_2(self, monkeypatch, tmp_path):
        # No data/ ancestor + no explicit dir → find_data_dir raises → exit 2
        fake = tmp_path / "x" / "y" / "z" / "w" / "scripts" / "slice_taxonomy.py"
        fake.parent.mkdir(parents=True)
        monkeypatch.setattr(st.os.path, "abspath", lambda _p: str(fake))
        rc = self._run(monkeypatch, ["auth", str(tmp_path / "o")])
        assert rc == 2


# ---------------------------------------------------------------------------
# CLI via subprocess (covers __main__ dispatch + argparse)
# ---------------------------------------------------------------------------
class TestCli:
    def test_cli_passthrough(self, run_plugin_script, tmp_path):
        data_dir = _seed_data_dir(tmp_path)
        out_dir = tmp_path / "cliout"
        res = run_plugin_script(
            "slice_taxonomy.py",
            "mystery-thing",
            str(out_dir),
            "--data-dir",
            str(data_dir),
        )
        assert res.returncode == 1
        assert "passthrough" in res.stdout

    def test_cli_profile(self, run_plugin_script, tmp_path):
        data_dir = _seed_data_dir(tmp_path)
        out_dir = tmp_path / "cliout2"
        res = run_plugin_script(
            "slice_taxonomy.py",
            "database",
            str(out_dir),
            "--data-dir",
            str(data_dir),
        )
        assert res.returncode == 0
        assert "database profile" in res.stdout
