"""Coverage-focused unit tests for scripts/baseline_state.py.

Drives the CLI subcommands (update / show / validate / check-fingerprint /
check-compat / check-changes / filter-diff-paths / dirty-set / last-run-info /
clean) and the internal helpers through real inputs, pinning current behaviour
(including the security-critical path heuristic). Test-file-only: no producer
edits.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

_spec = importlib.util.spec_from_file_location("baseline_state", SCRIPTS / "baseline_state.py")
baseline_state = importlib.util.module_from_spec(_spec)
sys.modules["baseline_state"] = baseline_state
assert _spec.loader is not None
_spec.loader.exec_module(baseline_state)

bs = baseline_state


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _make_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "package.json").write_text('{"name":"x","version":"1.0.0"}\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _ns(**kw) -> argparse.Namespace:
    return argparse.Namespace(**kw)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


def test_sha256_prefix(tmp_path: Path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello")
    h = bs._sha256(f)
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_scan_max_id_empty_and_found():
    assert bs._scan_max_id("no ids here", bs._T_ID_RE) == 0
    assert bs._scan_max_id("T-3 T-17 T-9", bs._T_ID_RE) == 17
    assert bs._scan_max_id("M-2 M-40", bs._M_ID_RE) == 40


def test_iter_repo_files_skips_junk(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "a.js").write_text("x")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x")
    (tmp_path / "package.json").write_text("{}")
    files = bs._iter_repo_files(tmp_path)
    names = {p.name for p in files}
    assert "app.py" in names
    assert "package.json" in names
    assert "a.js" not in names  # node_modules skipped


def test_iter_repo_files_exclude_prefix(tmp_path: Path):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "x.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    files = bs._iter_repo_files(tmp_path, exclude_rel_prefix="docs/security")
    rels = {p.relative_to(tmp_path).as_posix() for p in files}
    assert "package.json" in rels
    assert "docs/security/x.json" not in rels


def test_compute_recon_fingerprint_classifies(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "Dockerfile").write_text("FROM scratch")
    (tmp_path / "Dockerfile.dev").write_text("FROM scratch")
    (tmp_path / "main.tf").write_text("resource {}")
    (tmp_path / "docker-compose.yml").write_text("services: {}")
    k8s = tmp_path / "k8s"
    k8s.mkdir()
    (k8s / "deploy.yaml").write_text("kind: Deployment")
    fp = bs._compute_recon_fingerprint(tmp_path)
    assert "package.json" in fp["manifests"]
    assert "Dockerfile" in fp["dockerfiles"]
    assert "Dockerfile.dev" in fp["dockerfiles"]
    assert any("main.tf" in k for k in fp["iac"])
    assert any("docker-compose.yml" in k for k in fp["iac"])
    assert any("k8s/deploy.yaml" in k for k in fp["iac"])


def test_hash_stride_and_slice_files(tmp_path: Path):
    (tmp_path / ".stride-comp-a.json").write_text("{}")
    (tmp_path / ".actors-for-comp-a.json").write_text("{}")
    sf = bs._hash_stride_files(tmp_path)
    sl = bs._hash_slice_files(tmp_path)
    assert "comp-a" in sf and sf["comp-a"]["path"] == ".stride-comp-a.json"
    assert "comp-a" in sl and sl["comp-a"]["path"] == ".actors-for-comp-a.json"


def test_read_existing_missing_and_bad(tmp_path: Path):
    assert bs._read_existing(tmp_path / "nope.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert bs._read_existing(bad) == {}
    good = tmp_path / "good.json"
    good.write_text('{"a":1}')
    assert bs._read_existing(good) == {"a": 1}


def test_parse_manifest_hashes():
    assert bs._parse_manifest_hashes(None) is None
    assert bs._parse_manifest_hashes("") is None
    assert bs._parse_manifest_hashes("not json") is None
    assert bs._parse_manifest_hashes('{"no_manifests":1}') is None
    parsed = bs._parse_manifest_hashes('{"manifests":{"a":"h"}}')
    assert parsed == {"manifests": {"a": "h"}}


def test_parse_counter_via_update(tmp_path: Path):
    # Exercise _parse_counter through cmd_update with legacy T-/M- strings.
    out = tmp_path / "out"
    out.mkdir()
    repo = _make_git_repo(tmp_path)
    cache_dir = out / ".appsec-cache"
    cache_dir.mkdir()
    (cache_dir / "baseline.json").write_text(
        json.dumps({"id_counters": {"next_threat_id": "T-25", "next_mitigation_id": "M-9"}})
    )
    rc = bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    assert rc == 0
    data = json.loads((cache_dir / "baseline.json").read_text())
    assert data["id_counters"]["next_threat_id"] == 25
    assert data["id_counters"]["next_mitigation_id"] == 9


# ---------------------------------------------------------------------------
# cmd_update
# ---------------------------------------------------------------------------


def test_cmd_update_missing_output_dir(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    rc = bs.cmd_update(_ns(output_dir=str(tmp_path / "nope"), repo_root=str(repo), mode="full", manifest_hashes=None))
    assert rc == 1
    assert "output dir not found" in capsys.readouterr().err


def test_cmd_update_missing_repo_root(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    rc = bs.cmd_update(_ns(output_dir=str(out), repo_root=str(tmp_path / "norepo"), mode="full", manifest_hashes=None))
    assert rc == 1
    assert "repo root not found" in capsys.readouterr().err


def test_cmd_update_writes_baseline_and_carries_forward(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text("threats:\n  - id: T-007\nmitigations:\n  - id: M-003\n")
    cache_dir = out / ".appsec-cache"
    cache_dir.mkdir()
    (cache_dir / "baseline.json").write_text(json.dumps({"last_run_seconds": 99, "component_durations": {"c": 1}}))
    rc = bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="incremental", manifest_hashes=None))
    assert rc == 0
    data = json.loads((cache_dir / "baseline.json").read_text())
    assert data["id_counters"]["next_threat_id"] == 8
    assert data["id_counters"]["next_mitigation_id"] == 4
    assert data["last_run_seconds"] == 99  # carried forward
    assert data["component_durations"] == {"c": 1}
    assert data["mode"] == "incremental"


def test_cmd_update_mirrors_changelog_from_yaml(tmp_path: Path):
    # The committed changelog is mirrored into the (wipe-surviving) cache so a
    # lost threat-model.yaml can rehydrate history instead of resetting to v1.
    repo = _make_git_repo(tmp_path)
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text(
        "changelog:\n"
        "  - version: 1\n"
        "    date: '2026-06-19'\n"
        "    mode: full\n"
        "    threat_count: 31\n"
        "threats:\n  - id: T-001\n"
    )
    rc = bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    assert rc == 0
    data = json.loads((out / ".appsec-cache" / "baseline.json").read_text())
    assert data["changelog_mirror"][0]["date"] == "2026-06-19"
    assert data["changelog_mirror"][0]["threat_count"] == 31


def test_cmd_update_preserves_mirror_when_yaml_absent(tmp_path: Path):
    # A run whose yaml carries no changelog (or is gone) must never drop an
    # existing mirror — that would defeat the durability it provides.
    repo = _make_git_repo(tmp_path)
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    cache_dir = out / ".appsec-cache"
    cache_dir.mkdir()
    (cache_dir / "baseline.json").write_text(
        json.dumps({"changelog_mirror": [{"version": 1, "date": "2026-06-19", "mode": "full"}]})
    )
    # No threat-model.yaml on disk at all.
    rc = bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    assert rc == 0
    data = json.loads((cache_dir / "baseline.json").read_text())
    assert data["changelog_mirror"][0]["date"] == "2026-06-19"  # preserved


def test_cmd_update_with_precomputed_manifest_hashes(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    payload = json.dumps({"manifests": {"package.json": "sha256:abc"}, "dockerfiles": {}, "iac": {}})
    rc = bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=payload))
    assert rc == 0
    data = json.loads((out / ".appsec-cache" / "baseline.json").read_text())
    assert data["recon_fingerprint"]["manifests"] == {"package.json": "sha256:abc"}


def test_cmd_update_records_working_tree_snapshot(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    # Modify a tracked file so it appears dirty.
    (repo / "package.json").write_text('{"name":"x","version":"2.0.0"}\n')
    rc = bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    assert rc == 0
    data = json.loads((out / ".appsec-cache" / "baseline.json").read_text())
    assert "package.json" in data["working_tree_snapshot"]


# ---------------------------------------------------------------------------
# cmd_show / cmd_validate
# ---------------------------------------------------------------------------


def test_cmd_show_missing(tmp_path: Path, capsys):
    rc = bs.cmd_show(_ns(output_dir=str(tmp_path)))
    assert rc == 1
    assert "no cache" in capsys.readouterr().err


def test_cmd_show_prints(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text('{"schema_version":1}')
    rc = bs.cmd_show(_ns(output_dir=str(tmp_path)))
    assert rc == 0
    assert "schema_version" in capsys.readouterr().out


def test_cmd_validate_missing(tmp_path: Path, capsys):
    rc = bs.cmd_validate(_ns(output_dir=str(tmp_path)))
    assert rc == 1
    assert "no cache" in capsys.readouterr().err


def test_cmd_validate_invalid_json(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text("{broken")
    rc = bs.cmd_validate(_ns(output_dir=str(tmp_path)))
    assert rc == 2
    assert "invalid JSON" in capsys.readouterr().err


def test_cmd_validate_missing_keys(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(json.dumps({"schema_version": 99}))
    rc = bs.cmd_validate(_ns(output_dir=str(tmp_path)))
    assert rc == 2
    err = capsys.readouterr().err
    assert "schema_version != 1" in err
    assert "missing required key" in err


def test_cmd_validate_bad_analysis_version(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "recon_fingerprint": {"manifests": {}, "dockerfiles": {}, "iac": {}},
                "id_counters": {"next_threat_id": 1, "next_mitigation_id": 1},
                "stride_files": {},
                "analysis_version": "notint",
                "plugin_version": "1.0",
            }
        )
    )
    rc = bs.cmd_validate(_ns(output_dir=str(tmp_path)))
    assert rc == 2
    assert "analysis_version must be int" in capsys.readouterr().err


def test_cmd_validate_warns_missing_versions(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "recon_fingerprint": {"manifests": {}, "dockerfiles": {}, "iac": {}},
                "id_counters": {"next_threat_id": 1, "next_mitigation_id": 1},
                "stride_files": {},
            }
        )
    )
    rc = bs.cmd_validate(_ns(output_dir=str(tmp_path)))
    assert rc == 0
    err = capsys.readouterr().err
    assert "analysis_version missing" in err
    assert "plugin_version missing" in err


def test_cmd_validate_valid(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "recon_fingerprint": {"manifests": {}, "dockerfiles": {}, "iac": {}},
                "id_counters": {"next_threat_id": 1, "next_mitigation_id": 1},
                "stride_files": {},
                "analysis_version": 3,
                "plugin_version": "1.2.3",
            }
        )
    )
    rc = bs.cmd_validate(_ns(output_dir=str(tmp_path)))
    assert rc == 0
    assert "VALID" in capsys.readouterr().out


def test_cmd_validate_missing_fingerprint_subkeys(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "recon_fingerprint": {},  # missing manifests/dockerfiles/iac
                "id_counters": {},  # missing both counters
                "stride_files": {},
                "analysis_version": 1,
                "plugin_version": "1",
            }
        )
    )
    rc = bs.cmd_validate(_ns(output_dir=str(tmp_path)))
    assert rc == 2
    err = capsys.readouterr().err
    assert "recon_fingerprint.manifests missing" in err
    assert "id_counters.next_threat_id missing" in err


# ---------------------------------------------------------------------------
# version + sha extractors
# ---------------------------------------------------------------------------


def test_extract_analysis_version_from_yaml(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text("meta:\n  analysis_version: 5\n")
    v, src = bs._extract_baseline_analysis_version(tmp_path)
    assert v == 5 and src == "threat-model.yaml"


def test_extract_analysis_version_from_cache(tmp_path: Path):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(json.dumps({"analysis_version": 7}))
    v, src = bs._extract_baseline_analysis_version(tmp_path)
    assert v == 7 and src == "baseline.json"


def test_extract_analysis_version_missing(tmp_path: Path):
    v, src = bs._extract_baseline_analysis_version(tmp_path)
    assert v is None and src == "missing"


def test_extract_analysis_version_bad_cache(tmp_path: Path):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(json.dumps({"analysis_version": "x"}))
    v, src = bs._extract_baseline_analysis_version(tmp_path)
    assert v is None and src == "missing"


def test_extract_plugin_version_yaml_then_cache(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text("meta:\n  plugin_version: '1.4.0'\n")
    assert bs._extract_baseline_plugin_version(tmp_path) == "1.4.0"


def test_extract_plugin_version_from_cache(tmp_path: Path):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text(json.dumps({"plugin_version": "9.9"}))
    assert bs._extract_baseline_plugin_version(tmp_path) == "9.9"


def test_extract_plugin_version_none(tmp_path: Path):
    assert bs._extract_baseline_plugin_version(tmp_path) is None


def test_extract_commit_sha(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text("meta:\n  git:\n    commit_sha: 'abc1234'\n")
    assert bs._extract_baseline_commit_sha(tmp_path) == "abc1234"


def test_extract_commit_sha_none(tmp_path: Path):
    assert bs._extract_baseline_commit_sha(tmp_path) is None
    (tmp_path / "threat-model.yaml").write_text("meta: {}\n")
    assert bs._extract_baseline_commit_sha(tmp_path) is None


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------


def test_git_head_and_diff_names(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    head = bs._git_head(repo)
    assert head and len(head) >= 7
    # dirty working tree
    (repo / "package.json").write_text('{"name":"x","version":"3.0.0"}\n')
    (repo / "new.txt").write_text("untracked")
    committed, working = bs._git_diff_names(repo, head)
    assert "package.json" in working
    assert "new.txt" in working  # untracked picked up


def test_git_head_non_git(tmp_path: Path):
    assert bs._git_head(tmp_path) is None


def test_git_diff_names_no_base(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    committed, working = bs._git_diff_names(repo, None)
    assert committed == []


# ---------------------------------------------------------------------------
# relevance + security-critical classifiers
# ---------------------------------------------------------------------------


def test_classify_changed_files_relevance_empty():
    assert bs._classify_changed_files_relevance(Path("."), None, []) == ([], [], {})


def test_classify_changed_files_relevance_runs(tmp_path: Path):
    repo = _make_git_repo(tmp_path)
    rel, noise, reasons = bs._classify_changed_files_relevance(repo, None, ["src/auth.py", "README.md"])
    # whichever the filter decides, structure must hold
    assert isinstance(rel, list) and isinstance(noise, list) and isinstance(reasons, dict)
    assert set(rel) | set(noise) <= {"src/auth.py", "README.md"}


def test_classify_security_critical_pins_heuristic():
    paths = [
        "src/auth/login.py",
        "src/routes/api.js",
        "src/models/user.py",
        "src/migrations/001.sql",
        "README.md",
        "src/widget.css",
    ]
    hits = bs._classify_security_critical(paths)
    assert "src/auth/login.py" in hits
    assert "src/routes/api.js" in hits
    assert "src/models/user.py" in hits
    assert "src/migrations/001.sql" in hits
    assert "README.md" not in hits
    assert "src/widget.css" not in hits


def test_classify_security_critical_backslash_normalised():
    assert bs._classify_security_critical(["src\\Auth\\Token.cs"]) == ["src\\Auth\\Token.cs"]


# ---------------------------------------------------------------------------
# scan-excludes filter + output-dir-relative
# ---------------------------------------------------------------------------


def test_filter_diff_paths_empty():
    assert bs._filter_diff_paths_via_scan_excludes([], None) == []


def test_filter_diff_paths_drops_output_dir():
    kept = bs._filter_diff_paths_via_scan_excludes(
        ["docs/security/x.json", "src/app.py", "./src/lib.py"], "docs/security"
    )
    assert "docs/security/x.json" not in kept
    assert "src/app.py" in kept
    assert "./src/lib.py" in kept


def test_output_dir_relative_inside_and_outside(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    assert bs._output_dir_relative_to_repo(out, repo) == "docs/security"
    other = tmp_path / "elsewhere"
    other.mkdir()
    assert bs._output_dir_relative_to_repo(other, repo) is None


# ---------------------------------------------------------------------------
# content-hash incremental helpers
# ---------------------------------------------------------------------------


def test_build_baseline_content_hashes(tmp_path: Path):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    cp = cd / "baseline.json"
    cp.write_text(
        json.dumps(
            {
                "recon_fingerprint": {
                    "manifests": {"package.json": "sha256:aaa"},
                    "dockerfiles": {},
                    "iac": {},
                },
                "working_tree_snapshot": {"src/x.py": "sha256:bbb"},
            }
        )
    )
    out = bs._build_baseline_content_hashes(cp)
    assert out["package.json"] == "aaa"
    assert out["src/x.py"] == "bbb"


def test_split_unchanged_vs_baseline(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_text("data")
    h = bs._sha256(f).split(":", 1)[-1]
    baseline = {"a.txt": h, "gone.txt": "deadbeef"}
    changed, unchanged = bs._split_unchanged_vs_baseline(tmp_path, ["a.txt", "gone.txt", "new.txt"], baseline)
    assert "a.txt" in unchanged
    assert "gone.txt" in changed  # hash differs
    assert "new.txt" in changed  # no recorded hash


def test_split_unchanged_no_baseline(tmp_path: Path):
    changed, unchanged = bs._split_unchanged_vs_baseline(tmp_path, ["a", "b"], {})
    assert changed == ["a", "b"] and unchanged == []


def test_split_unchanged_unreadable(tmp_path: Path):
    # recorded hash present but file missing on disk -> OSError -> changed
    changed, unchanged = bs._split_unchanged_vs_baseline(tmp_path, ["missing.txt"], {"missing.txt": "abc"})
    assert changed == ["missing.txt"] and unchanged == []


# ---------------------------------------------------------------------------
# cmd_check_fingerprint
# ---------------------------------------------------------------------------


def test_check_fingerprint_no_cache(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    rc = bs.cmd_check_fingerprint(_ns(output_dir=str(out), repo_root=str(repo), require_clean_tree=False))
    assert rc == 1
    assert "no baseline cache" in capsys.readouterr().err


def test_check_fingerprint_bad_cache(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = tmp_path / "out"
    (out / ".appsec-cache").mkdir(parents=True)
    (out / ".appsec-cache" / "baseline.json").write_text("{broken")
    rc = bs.cmd_check_fingerprint(_ns(output_dir=str(out), repo_root=str(repo), require_clean_tree=False))
    assert rc == 2
    assert "cannot read baseline cache" in capsys.readouterr().err


def test_check_fingerprint_match(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    rc = bs.cmd_check_fingerprint(_ns(output_dir=str(out), repo_root=str(repo), require_clean_tree=False))
    assert rc == 0
    assert "unchanged" in capsys.readouterr().out


def test_check_fingerprint_changed(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    # add a new manifest -> fingerprint changes
    (repo / "requirements.txt").write_text("flask\n")
    rc = bs.cmd_check_fingerprint(_ns(output_dir=str(out), repo_root=str(repo), require_clean_tree=False))
    assert rc == 1
    assert "changed" in capsys.readouterr().out


def test_check_fingerprint_require_clean_tree_no_sha(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    # no threat-model.yaml -> no baseline sha -> not git-provable
    rc = bs.cmd_check_fingerprint(_ns(output_dir=str(out), repo_root=str(repo), require_clean_tree=True))
    assert rc == 1
    assert "not git-provable" in capsys.readouterr().err


def test_check_fingerprint_require_clean_tree_dirty(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    head = _head(repo)
    (out / "threat-model.yaml").write_text(f"meta:\n  git:\n    commit_sha: '{head}'\n")
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    # dirty a non-manifest source file (fingerprint stays same, tree dirty)
    (repo / "app.py").write_text("print('x')\n")
    rc = bs.cmd_check_fingerprint(_ns(output_dir=str(out), repo_root=str(repo), require_clean_tree=True))
    assert rc == 1
    assert "not clean" in capsys.readouterr().out


def test_check_fingerprint_require_clean_tree_clean(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    head = _head(repo)
    (out / "threat-model.yaml").write_text(f"meta:\n  git:\n    commit_sha: '{head}'\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add tm")
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    head2 = _head(repo)
    (out / "threat-model.yaml").write_text(f"meta:\n  git:\n    commit_sha: '{head2}'\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "tm2")
    head3 = _head(repo)
    (out / "threat-model.yaml").write_text(f"meta:\n  git:\n    commit_sha: '{head3}'\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "tm3")
    rc = bs.cmd_check_fingerprint(_ns(output_dir=str(out), repo_root=str(repo), require_clean_tree=True))
    # fingerprint unchanged + tree clean vs baseline_sha
    assert rc == 0
    assert "may be skipped" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# cmd_check_compat
# ---------------------------------------------------------------------------


def test_check_compat_missing_dir(tmp_path: Path, capsys):
    rc = bs.cmd_check_compat(_ns(output_dir=str(tmp_path / "nope")))
    # plugin_meta may or may not be importable; both branches return >0 here
    assert rc in (2,)


def test_check_compat_runs(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("meta:\n  analysis_version: 1\n")
    rc = bs.cmd_check_compat(_ns(output_dir=str(out)))
    # exit code depends on plugin_meta classification; just assert it emitted
    captured = capsys.readouterr()
    assert "BASELINE_COMPAT" in (captured.out + captured.err) or rc == 2


# ---------------------------------------------------------------------------
# cmd_check_changes
# ---------------------------------------------------------------------------


def test_check_changes_missing_output_dir(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    rc = bs.cmd_check_changes(_ns(output_dir=str(tmp_path / "nope"), repo_root=str(repo), base_ref=None))
    assert rc == 3
    assert "output_dir missing" in capsys.readouterr().out


def test_check_changes_no_baseline(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    rc = bs.cmd_check_changes(_ns(output_dir=str(out), repo_root=str(repo), base_ref=None))
    assert rc == 3
    assert "no_baseline" in capsys.readouterr().out


def test_check_changes_unchanged(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    head = _head(repo)
    (out / "threat-model.yaml").write_text(f"meta:\n  git:\n    commit_sha: '{head}'\n")
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    capsys.readouterr()  # drop the "wrote baseline" line
    rc = bs.cmd_check_changes(_ns(output_dir=str(out), repo_root=str(repo), base_ref=head))
    payload = json.loads(capsys.readouterr().out)
    # no source changes + fingerprint match -> unchanged (0) or plugin-drift (10)
    assert rc in (0, 10)
    assert payload["status"] in ("unchanged", "unchanged_plugin_drift")


def test_check_changes_security_relevant(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    head = _head(repo)
    (out / "threat-model.yaml").write_text(f"meta:\n  git:\n    commit_sha: '{head}'\n")
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    # add a clearly security-relevant new file
    (repo / "auth.py").write_text("def login(): pass\n")
    capsys.readouterr()  # drop the "wrote baseline" line
    rc = bs.cmd_check_changes(_ns(output_dir=str(out), repo_root=str(repo), base_ref=head))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["status"] == "changed"


def test_check_changes_base_ref_override(tmp_path: Path, capsys):
    repo = _make_git_repo(tmp_path)
    out = repo / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("meta:\n  git:\n    commit_sha: 'deadbee'\n")
    bs.cmd_update(_ns(output_dir=str(out), repo_root=str(repo), mode="full", manifest_hashes=None))
    capsys.readouterr()  # drop the "wrote baseline" line
    rc = bs.cmd_check_changes(_ns(output_dir=str(out), repo_root=str(repo), base_ref=_head(repo)))
    assert rc in (0, 1, 2, 10)
    json.loads(capsys.readouterr().out)  # valid JSON


# ---------------------------------------------------------------------------
# glob -> regex + component parsing
# ---------------------------------------------------------------------------


def test_glob_to_regex_patterns():
    assert bs._glob_to_regex("src/*.py").match("src/a.py")
    assert not bs._glob_to_regex("src/*.py").match("src/sub/a.py")
    assert bs._glob_to_regex("src/**/x.py").match("src/a/b/x.py")
    assert bs._glob_to_regex("src/**/x.py").match("src/x.py")
    assert bs._glob_to_regex("a?.py").match("ab.py")
    assert not bs._glob_to_regex("a?.py").match("a/.py")
    assert bs._glob_to_regex("a.b+c").match("a.b+c")  # special chars escaped


def test_parse_components_from_yaml_missing(tmp_path: Path):
    assert bs._parse_components_from_yaml(tmp_path / "nope.yaml") == []


def test_parse_components_from_yaml_regex_fallback(tmp_path: Path, monkeypatch):
    # Force the PyYAML import to fail so the regex fallback path runs.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    y = tmp_path / "threat-model.yaml"
    y.write_text("components:\n- id: comp-a\n  type: service\n  paths:\n    - src/a/foo.py\n    - src/a/bar.py\n")
    comps = bs._parse_components_from_yaml(y)
    by_id = {c["id"]: c for c in comps}
    assert "comp-a" in by_id
    assert "src/a/foo.py" in by_id["comp-a"]["paths"]


def test_parse_components_from_yaml_pyyaml(tmp_path: Path):
    y = tmp_path / "threat-model.yaml"
    y.write_text(
        "components:\n"
        "  - id: comp-a\n"
        "    paths:\n"
        "      - src/a/**\n"
        "  - id: nopaths\n"  # no paths key -> defaults to [] (still a list -> kept)
        "  - not-a-dict\n"  # non-dict entry -> skipped
    )
    comps = bs._parse_components_from_yaml(y)
    by_id = {c["id"]: c for c in comps}
    assert "comp-a" in by_id
    assert by_id["comp-a"]["paths"] == ["src/a/**"]
    # Pin current behavior: missing-paths component kept with empty path list.
    assert "nopaths" in by_id
    assert by_id["nopaths"]["paths"] == []


# ---------------------------------------------------------------------------
# cmd_dirty_set
# ---------------------------------------------------------------------------


def _dirty_ns(out: Path, files=None, no_stdin=True):
    return _ns(output_dir=str(out), files=files, no_stdin=no_stdin)


def test_dirty_set_dirty(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("components:\n  - id: api\n    paths:\n      - src/api/**\n")
    rc = bs.cmd_dirty_set(_dirty_ns(out, files=["src/api/routes.py"]))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["decision"] == "dirty"
    assert "api" in payload["dirty_component_ids"]


def test_dirty_set_noop_global(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("components:\n  - id: api\n    paths:\n      - src/api/**\n")
    rc = bs.cmd_dirty_set(_dirty_ns(out, files=["package.json"]))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["decision"] == "noop_global_only"


def test_dirty_set_ambiguous(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("components:\n  - id: api\n    paths:\n      - src/api/**\n")
    rc = bs.cmd_dirty_set(_dirty_ns(out, files=["src/brandnew/widget.py"]))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert payload["decision"] == "ambiguous_potential_new_component"


def test_dirty_set_empty_input(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("components: []\n")
    rc = bs.cmd_dirty_set(_dirty_ns(out, files=[]))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["decision"] == "noop_empty_input"


def test_dirty_set_reads_stdin(tmp_path: Path, capsys, monkeypatch):
    import io

    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("components:\n  - id: api\n    paths:\n      - src/api/**\n")

    class _Stdin(io.StringIO):
        def isatty(self):
            return False

    monkeypatch.setattr(bs.sys, "stdin", _Stdin("src/api/handler.py\n\n"))
    rc = bs.cmd_dirty_set(_ns(output_dir=str(out), files=None, no_stdin=False))
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert "api" in payload["dirty_component_ids"]


def test_filter_diff_paths_reads_stdin(tmp_path: Path, capsys, monkeypatch):
    import io

    repo = tmp_path / "repo"
    out = repo / "docs" / "security"
    out.mkdir(parents=True)

    class _Stdin(io.StringIO):
        def isatty(self):
            return False

    monkeypatch.setattr(bs.sys, "stdin", _Stdin("src/app.py\n"))
    rc = bs.cmd_filter_diff_paths(
        _ns(output_dir=str(out), repo_root=str(repo), format="lines", no_stdin=False, paths=None)
    )
    assert rc == 0
    assert "src/app.py" in capsys.readouterr().out


def test_classify_relevance_fallback_on_import_error(tmp_path: Path, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "security_relevance_filter":
            raise ImportError("boom")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rel, noise, reasons = bs._classify_changed_files_relevance(tmp_path, None, ["src/a.py"])
    # conservative fallback: everything relevant, no reasons
    assert rel == ["src/a.py"]
    assert noise == []
    assert reasons == {}


def test_filter_diff_paths_helper_import_error(tmp_path: Path, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "scan_excludes":
            raise ImportError("boom")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # On loader failure the input list is returned unchanged.
    assert bs._filter_diff_paths_via_scan_excludes(["a", "b"], "docs/security") == ["a", "b"]


def test_dirty_set_normalises_dot_slash(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("components:\n  - id: api\n    paths:\n      - src/api/**\n")
    rc = bs.cmd_dirty_set(_dirty_ns(out, files=["./src/api/x.py"]))
    assert rc == 0
    json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# cmd_filter_diff_paths
# ---------------------------------------------------------------------------


def test_filter_diff_paths_cli_lines(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    rc = bs.cmd_filter_diff_paths(
        _ns(
            output_dir=str(out),
            repo_root=str(repo),
            format="lines",
            no_stdin=True,
            paths=["src/app.py", "docs/security/x.json"],
        )
    )
    assert rc == 0
    out_text = capsys.readouterr().out
    assert "src/app.py" in out_text
    assert "docs/security/x.json" not in out_text


def test_filter_diff_paths_cli_json(tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    rc = bs.cmd_filter_diff_paths(
        _ns(
            output_dir=str(out),
            repo_root=str(repo),
            format="json",
            no_stdin=True,
            paths=["src/app.py", "docs/security/x.json", "src/app.py"],
        )
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "src/app.py" in payload["paths"]
    assert payload["excluded_count"] >= 1


# ---------------------------------------------------------------------------
# cmd_last_run_info
# ---------------------------------------------------------------------------


def test_last_run_info_no_baseline(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    rc = bs.cmd_last_run_info(_ns(output_dir=str(out)))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["has_baseline"] is False


def test_last_run_info_with_baseline_and_yaml(tmp_path: Path, capsys):
    out = tmp_path / "out"
    cd = out / ".appsec-cache"
    cd.mkdir(parents=True)
    (cd / "baseline.json").write_text(
        json.dumps({"plugin_version": "1.0", "analysis_version": 2, "last_run_at": "2026-01-01T00:00:00Z"})
    )
    (out / "threat-model.yaml").write_text("meta:\n  git:\n    commit_sha: 'abc1234'\n")
    rc = bs.cmd_last_run_info(_ns(output_dir=str(out)))
    payload = json.loads(capsys.readouterr().out)
    assert payload["has_baseline"] is True
    assert payload["plugin_version"] == "1.0"
    assert payload["commit_sha"] == "abc1234"


def test_last_run_info_bad_cache(tmp_path: Path, capsys):
    out = tmp_path / "out"
    cd = out / ".appsec-cache"
    cd.mkdir(parents=True)
    (cd / "baseline.json").write_text("{broken")
    rc = bs.cmd_last_run_info(_ns(output_dir=str(out)))
    payload = json.loads(capsys.readouterr().out)
    assert payload["has_baseline"] is False


def test_last_run_info_plugin_version_from_yaml(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("meta:\n  plugin_version: '2.2'\n  git:\n    commit_sha: 'abc1234'\n")
    rc = bs.cmd_last_run_info(_ns(output_dir=str(out)))
    payload = json.loads(capsys.readouterr().out)
    assert payload["plugin_version"] == "2.2"


# ---------------------------------------------------------------------------
# cmd_clean + _collect_removal_targets
# ---------------------------------------------------------------------------


def _make_dirty_output(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "threat-model.md").write_text("product")
    (out / ".recon-summary.md").write_text("cache")
    (out / ".stride-c.json").write_text("{}")
    (out / ".appsec-lock").write_text("123")
    (out / ".agent-run.log").write_text("audit")
    (out / "mystery.txt").write_text("unknown")
    cache_dir = out / ".appsec-cache"
    cache_dir.mkdir(exist_ok=True)
    (cache_dir / "baseline.json").write_text("{}")
    prog = out / ".progress"
    prog.mkdir(exist_ok=True)
    (prog / "p.json").write_text("{}")


def test_collect_removal_targets_cache_mode(tmp_path: Path):
    out = tmp_path / "out"
    _make_dirty_output(out)
    t = bs._collect_removal_targets(out, "cache")
    cache_names = {p.name for p in t["cache"]}
    assert ".recon-summary.md" in cache_names
    assert ".stride-c.json" in cache_names
    assert ".appsec-cache" in cache_names
    assert t["product"] == []  # preserved in cache mode
    assert t["audit"] == []
    assert any(p.name == "mystery.txt" for p in t["unknown"])


def test_collect_removal_targets_all_mode(tmp_path: Path):
    out = tmp_path / "out"
    _make_dirty_output(out)
    t = bs._collect_removal_targets(out, "all")
    assert any(p.name == "threat-model.md" for p in t["product"])
    assert any(p.name == ".agent-run.log" for p in t["audit"])


def test_collect_removal_targets_missing_dir(tmp_path: Path):
    t = bs._collect_removal_targets(tmp_path / "nope", "all")
    assert t == {"cache": [], "transient": [], "product": [], "audit": [], "unknown": []}


def test_cmd_clean_bad_mode(tmp_path: Path, capsys):
    rc = bs.cmd_clean(_ns(output_dir=str(tmp_path), mode="weird", dry_run=False, force=False))
    assert rc == 2
    assert "unknown --mode" in capsys.readouterr().err


def test_cmd_clean_missing_dir(tmp_path: Path, capsys):
    rc = bs.cmd_clean(_ns(output_dir=str(tmp_path / "nope"), mode="cache", dry_run=False, force=False))
    assert rc == 0
    assert "does not exist" in capsys.readouterr().out


def test_cmd_clean_not_a_dir(tmp_path: Path, capsys):
    f = tmp_path / "afile"
    f.write_text("x")
    rc = bs.cmd_clean(_ns(output_dir=str(f), mode="cache", dry_run=False, force=False))
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err


def test_cmd_clean_nothing_to_clean(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "mystery.txt").write_text("x")  # unknown, never removed
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="cache", dry_run=False, force=False))
    assert rc == 0
    assert "nothing to clean" in capsys.readouterr().out


def test_cmd_clean_dry_run(tmp_path: Path, capsys):
    out = tmp_path / "out"
    _make_dirty_output(out)
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="cache", dry_run=True, force=False))
    assert rc == 0
    text = capsys.readouterr().out
    assert "dry run" in text
    assert "unknown/preserved" in text
    # nothing removed
    assert (out / ".recon-summary.md").exists()


def test_cmd_clean_cache_executes(tmp_path: Path, capsys):
    out = tmp_path / "out"
    _make_dirty_output(out)
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="cache", dry_run=False, force=False))
    assert rc == 0
    assert not (out / ".recon-summary.md").exists()
    assert not (out / ".appsec-cache").exists()
    # product + audit + unknown preserved
    assert (out / "threat-model.md").exists()
    assert (out / ".agent-run.log").exists()
    assert (out / "mystery.txt").exists()


def test_cmd_clean_all_force(tmp_path: Path, capsys):
    out = tmp_path / "out"
    _make_dirty_output(out)
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="all", dry_run=False, force=True))
    assert rc == 0
    assert not (out / "threat-model.md").exists()
    assert not (out / ".agent-run.log").exists()
    # unknown still preserved -> dir not empty -> dir not removed
    assert out.exists()
    assert (out / "mystery.txt").exists()


def test_cmd_clean_all_removes_empty_dir(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text("p")
    (out / ".recon-summary.md").write_text("c")
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="all", dry_run=False, force=True))
    assert rc == 0
    assert not out.exists()  # emptied then removed


def test_cmd_clean_all_declined(tmp_path: Path, monkeypatch, capsys):
    out = tmp_path / "out"
    _make_dirty_output(out)
    monkeypatch.setattr(bs.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("APPSEC_CI_MODE", "")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="all", dry_run=False, force=False))
    assert rc == 1
    assert "Aborted" in capsys.readouterr().out
    assert (out / "threat-model.md").exists()


def test_cmd_clean_all_confirmed(tmp_path: Path, monkeypatch, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text("p")
    monkeypatch.setattr(bs.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("APPSEC_CI_MODE", "")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="all", dry_run=False, force=False))
    assert rc == 0
    assert not (out / "threat-model.md").exists()


def test_cmd_clean_all_ci_mode_skips_prompt(tmp_path: Path, monkeypatch, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text("p")
    monkeypatch.setattr(bs.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("APPSEC_CI_MODE", "1")  # CI -> no prompt despite tty
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="all", dry_run=False, force=False))
    assert rc == 0
    assert not (out / "threat-model.md").exists()


def test_cmd_clean_all_eof_declines(tmp_path: Path, monkeypatch, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text("p")
    monkeypatch.setattr(bs.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("APPSEC_CI_MODE", "")

    def _raise(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise)
    rc = bs.cmd_clean(_ns(output_dir=str(out), mode="all", dry_run=False, force=False))
    assert rc == 1
    assert (out / "threat-model.md").exists()


# ---------------------------------------------------------------------------
# main() / _parse_args dispatch
# ---------------------------------------------------------------------------


def test_main_show_missing(tmp_path: Path, capsys):
    rc = bs.main(["show", "--output-dir", str(tmp_path)])
    assert rc == 1


def test_main_validate_dispatch(tmp_path: Path, capsys):
    cd = tmp_path / ".appsec-cache"
    cd.mkdir()
    (cd / "baseline.json").write_text("{broken")
    rc = bs.main(["validate", "--output-dir", str(tmp_path)])
    assert rc == 2


def test_main_clean_dispatch(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    rc = bs.main(["clean", "--output-dir", str(out), "--mode", "cache"])
    assert rc == 0


def test_main_requires_subcommand(capsys):
    with pytest.raises(SystemExit):
        bs.main([])


def test_main_dirty_set_dispatch(tmp_path: Path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.yaml").write_text("components: []\n")
    rc = bs.main(["dirty-set", "--output-dir", str(out), "--no-stdin", "--files"])
    assert rc == 2
