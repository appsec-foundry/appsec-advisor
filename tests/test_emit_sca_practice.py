from __future__ import annotations

import ast
import json
from pathlib import Path

import emit_sca_practice as sca
import pytest


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _controls(output_dir: Path) -> dict[str, dict]:
    data = json.loads((output_dir / ".security-controls.json").read_text(encoding="utf-8"))
    return {row["control"]: row for row in data["security_controls"]}


def _findings(output_dir: Path) -> list[dict]:
    data = json.loads((output_dir / ".sca-practice-findings.json").read_text(encoding="utf-8"))
    return data["findings"]


def test_complete_npm_posture_emits_adequate_controls_without_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"express": "^4.18.0"}}\n')
    _write(repo / "package-lock.json", '{"lockfileVersion": 3}\n')
    _write(repo / ".github" / "workflows" / "sca.yml", "steps:\n  - run: npm audit --audit-level=high\n")
    _write(
        repo / ".github" / "dependabot.yml",
        "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule: {interval: weekly}\n",
    )

    assert sca.run(repo, out, "Tier 1", Path.cwd()) == 0

    controls = _controls(out)
    assert controls[sca.CONTROL_SCANNING]["effectiveness"] == "Adequate"
    assert controls[sca.CONTROL_UPDATES]["effectiveness"] == "Adequate"
    assert controls[sca.CONTROL_LOCKFILE]["effectiveness"] == "Adequate"
    assert _findings(out) == []


def test_missing_and_partial_controls_emit_sidecar_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"express": "^4.18.0"}}\n')
    _write(repo / "requirements.txt", "flask==3.0.0\n")
    _write(repo / "package-lock.json", '{"lockfileVersion": 3}\n')
    _write(repo / ".github" / "workflows" / "sca.yml", "steps:\n  - run: trivy fs .\n")

    assert sca.run(repo, out, "T2", Path.cwd()) == 0

    controls = _controls(out)
    assert controls[sca.CONTROL_SCANNING]["effectiveness"] == "Partial"
    assert controls[sca.CONTROL_UPDATES]["effectiveness"] == "Missing"
    assert controls[sca.CONTROL_LOCKFILE]["effectiveness"] == "Partial"
    findings = _findings(out)
    assert {f["control"] for f in findings} == {
        sca.CONTROL_SCANNING,
        sca.CONTROL_UPDATES,
        sca.CONTROL_LOCKFILE,
    }
    assert {f["source"] for f in findings} == {"sca-practice"}
    assert all(f["derived_from"] == [] for f in findings)


def test_active_dependency_update_cadence_lifts_updates_to_partial(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "package.json", '{"dependencies": {"express": "^4.18.0"}}\n')
    _write(
        out / ".dep-update-activity.json",
        json.dumps({"cadence": "active", "dep_update_commits": 3, "window_days": 90}),
    )

    effectiveness, evidence = sca.classify_auto_updates(repo, out)

    assert effectiveness == "Partial"
    assert evidence == ["git-log: 3 dep-update commit(s) in last 90 days (cadence=active)"]


def test_emitter_does_not_execute_package_manager_or_network_tools() -> None:
    tree = ast.parse((Path.cwd() / "scripts" / "emit_sca_practice.py").read_text(encoding="utf-8"))
    forbidden_imports = {"subprocess", "urllib", "requests", "httpx"}
    forbidden_module_calls = {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "run"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("urllib", "urlopen"),
    }

    imports: set[str] = set()
    calls: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                calls.add((func.value.id, func.attr))

    assert not (imports & forbidden_imports)
    assert not (calls & forbidden_module_calls)


# ---------------------------------------------------------------------------
# Tier normalization
# ---------------------------------------------------------------------------


def test_normalize_tier_none_defaults_t2() -> None:
    assert sca._normalize_tier(None) == "T2"


def test_normalize_tier_unparseable_defaults_t2() -> None:
    assert sca._normalize_tier("Restricted") == "T2"


def test_normalize_tier_variants() -> None:
    assert sca._normalize_tier("Tier 1 — Restricted") == "T1"
    assert sca._normalize_tier("T3") == "T3"
    assert sca._normalize_tier("tier 4") == "T4"


# ---------------------------------------------------------------------------
# CI file reading / scanning hits
# ---------------------------------------------------------------------------


def test_read_ci_files_skips_directory_named_like_workflow(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "Jenkinsfile").mkdir(parents=True)  # a directory, not a file
    assert sca._read_ci_files(repo) == []


def test_classify_sca_scanning_no_ci_is_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Missing"
    assert ev == []


def test_classify_sca_scanning_ci_without_tool_is_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / ".github" / "workflows" / "ci.yml", "steps:\n  - run: echo hi\n")
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Missing"
    assert ev == []


def test_classify_sca_scanning_records_line_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / "package-lock.json", "{}\n")
    _write(repo / ".github" / "workflows" / "ci.yml", "steps:\n  - run: snyk test\n")
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Adequate"
    assert ev == [".github/workflows/ci.yml:2"]


# ---------------------------------------------------------------------------
# Auto-updates / renovate / dependabot multi-eco coverage
# ---------------------------------------------------------------------------


def test_renovate_config_is_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    out.mkdir()
    _write(repo / "package.json", "{}\n")
    _write(repo / "renovate.json", "{}\n")
    eff, ev = sca.classify_auto_updates(repo, out)
    assert eff == "Adequate"
    assert "renovate.json:1" in ev


def test_load_activity_sidecar_malformed_json_is_unknown(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(out / ".dep-update-activity.json", "{not valid json")
    assert sca._load_activity_sidecar(out) == {"cadence": "unknown"}


def test_load_activity_sidecar_absent_is_unknown(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert sca._load_activity_sidecar(out) == {"cadence": "unknown"}


def test_auto_updates_no_config_no_activity_is_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    out.mkdir()
    _write(repo / "package.json", "{}\n")
    eff, ev = sca.classify_auto_updates(repo, out)
    assert eff == "Missing"
    assert ev == []


def test_auto_updates_dependabot_incomplete_eco_coverage_is_partial(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    out.mkdir()
    # Two ecosystems (npm + pip) but dependabot only covers npm → Partial.
    _write(repo / "package.json", "{}\n")
    _write(repo / "requirements.txt", "flask\n")
    _write(
        repo / ".github" / "dependabot.yml",
        "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule: {interval: weekly}\n",
    )
    eff, _ = sca.classify_auto_updates(repo, out)
    assert eff == "Partial"


def test_auto_updates_dependabot_full_eco_coverage_is_adequate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    out.mkdir()
    _write(repo / "package.json", "{}\n")
    _write(repo / "requirements.txt", "flask\n")
    _write(
        repo / ".github" / "dependabot.yml",
        "version: 2\nupdates:\n"
        "  - package-ecosystem: npm\n    directory: /\n    schedule: {interval: weekly}\n"
        "  - package-ecosystem: pip\n    directory: /\n    schedule: {interval: weekly}\n",
    )
    eff, _ = sca.classify_auto_updates(repo, out)
    assert eff == "Adequate"


def test_auto_updates_dependabot_malformed_yaml_falls_through(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    out.mkdir()
    _write(repo / "package.json", "{}\n")
    _write(repo / "requirements.txt", "flask\n")
    # Unparseable dependabot config → except branch → treated Adequate (no downgrade).
    _write(repo / ".github" / "dependabot.yml", "version: 2\nupdates: [ : : :\n")
    eff, _ = sca.classify_auto_updates(repo, out)
    assert eff == "Adequate"


# ---------------------------------------------------------------------------
# Lockfile hygiene
# ---------------------------------------------------------------------------


def test_lockfile_no_ecosystems_is_adequate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    eff, ev = sca.classify_lockfile_hygiene(repo)
    assert eff == "Adequate"
    assert ev == []


def test_lockfile_all_missing_is_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "go.mod", "module x\n")
    eff, ev = sca.classify_lockfile_hygiene(repo)
    assert eff == "Missing"
    assert ev == []


def test_lockfile_present_is_adequate_and_skips_vendored(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "go.mod", "module x\n")
    # Vendored lockfile under node_modules must be ignored ...
    _write(repo / "node_modules" / "dep" / "go.sum", "x\n")
    # ... but the real one at root counts.
    _write(repo / "go.sum", "x\n")
    eff, ev = sca.classify_lockfile_hygiene(repo)
    assert eff == "Adequate"
    assert ev == ["go.sum:1"]


def test_lockfile_partial_when_one_eco_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / "package-lock.json", "{}\n")
    _write(repo / "go.mod", "module x\n")  # no go.sum
    eff, _ = sca.classify_lockfile_hygiene(repo)
    assert eff == "Partial"


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------


def test_detect_ecosystems_skips_build_dirs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "dist" / "package.json", "{}\n")
    _write(repo / "vendor" / "go.mod", "module x\n")
    assert sca._detect_ecosystems(repo) == set()


def test_detect_ecosystems_finds_manifests(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "Cargo.toml", "[package]\n")
    assert sca._detect_ecosystems(repo) == {"cargo"}


# ---------------------------------------------------------------------------
# Security-controls sidecar loading / upsert
# ---------------------------------------------------------------------------


def test_load_existing_controls_absent_returns_default(tmp_path: Path) -> None:
    data = sca._load_existing_security_controls(tmp_path / "nope.json")
    assert data == {"schema_version": 1, "security_controls": []}


def test_load_existing_controls_non_dict_returns_default(tmp_path: Path) -> None:
    p = tmp_path / "sc.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    assert sca._load_existing_security_controls(p) == {"schema_version": 1, "security_controls": []}


def test_load_existing_controls_malformed_returns_default(tmp_path: Path) -> None:
    p = tmp_path / "sc.json"
    p.write_text("{not json", encoding="utf-8")
    assert sca._load_existing_security_controls(p) == {"schema_version": 1, "security_controls": []}


def test_load_existing_controls_fills_defaults(tmp_path: Path) -> None:
    p = tmp_path / "sc.json"
    p.write_text("{}", encoding="utf-8")
    data = sca._load_existing_security_controls(p)
    assert data["schema_version"] == 1
    assert data["security_controls"] == []


def test_run_preserves_hand_authored_rows(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "go.mod", "module x\n")
    custom = {
        "domain": "Some Other Domain",
        "control": "Hand-authored control",
        "effectiveness": "Adequate",
    }
    (out / ".security-controls.json").write_text(
        json.dumps({"schema_version": 1, "security_controls": [custom]}), encoding="utf-8"
    )
    assert sca.run(repo, out, "T2", Path.cwd()) == 0
    controls = _controls(out)
    assert "Hand-authored control" in controls
    # And running twice is idempotent (no duplicate SCA rows).
    assert sca.run(repo, out, "T2", Path.cwd()) == 0
    data = json.loads((out / ".security-controls.json").read_text(encoding="utf-8"))
    sca_rows = [r for r in data["security_controls"] if r["control"] in sca.SCA_CONTROLS]
    assert len(sca_rows) == 3


# ---------------------------------------------------------------------------
# Severity policy
# ---------------------------------------------------------------------------


def test_load_severity_policy_absent_returns_empty(tmp_path: Path) -> None:
    assert sca._load_severity_policy(tmp_path) == {}


def test_load_severity_policy_malformed_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "sca-practice-severity.yaml").write_text("a: [: :\n", encoding="utf-8")
    assert sca._load_severity_policy(tmp_path) == {}


def test_load_severity_policy_real_file() -> None:
    policy = sca._load_severity_policy(Path.cwd())
    assert "missing_severity" in policy


def test_severity_for_missing_partial_adequate() -> None:
    policy = sca._load_severity_policy(Path.cwd())
    assert sca._severity_for(policy, sca.CONTROL_SCANNING, "T1", "Missing") == "Critical"
    assert sca._severity_for(policy, sca.CONTROL_SCANNING, "T1", "Partial") == "High"
    assert sca._severity_for(policy, sca.CONTROL_SCANNING, "T1", "Adequate") == "Informational"


def test_severity_for_unknown_tier_falls_back_default() -> None:
    policy = sca._load_severity_policy(Path.cwd())
    # Tier not in matrix → falls back to default_tier column (T2), else Medium.
    val = sca._severity_for(policy, sca.CONTROL_SCANNING, "T9", "Missing")
    assert val == sca._severity_for(policy, sca.CONTROL_SCANNING, "T2", "Missing")


def test_severity_for_empty_policy_defaults_medium() -> None:
    assert sca._severity_for({}, sca.CONTROL_SCANNING, "T1", "Missing") == "Medium"


# ---------------------------------------------------------------------------
# Assessment / summary text
# ---------------------------------------------------------------------------


def test_assessment_text_adequate_without_evidence() -> None:
    txt = sca._assessment_text(sca.CONTROL_SCANNING, "Adequate", [])
    assert "no specific evidence" in txt


def test_assessment_text_partial_and_missing() -> None:
    assert "partial" in sca._assessment_text(sca.CONTROL_LOCKFILE, "Partial", []).lower()
    assert "not detected" in sca._assessment_text(sca.CONTROL_LOCKFILE, "Missing", [])


# ---------------------------------------------------------------------------
# main() / argparse / CLI exits
# ---------------------------------------------------------------------------


def test_main_repo_root_not_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "out"
    out.mkdir()
    rc = sca.main(["--repo-root", str(tmp_path / "missing"), "--output-dir", str(out)])
    assert rc == 2
    assert "repo-root not a directory" in capsys.readouterr().err


def test_main_output_dir_not_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    rc = sca.main(["--repo-root", str(repo), "--output-dir", str(tmp_path / "missing")])
    assert rc == 2
    assert "output-dir not a directory" in capsys.readouterr().err


def test_main_happy_path_uses_plugin_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "go.mod", "module x\n")
    rc = sca.main(
        [
            "--repo-root",
            str(repo),
            "--output-dir",
            str(out),
            "--asset-tier",
            "T1",
            "--plugin-root",
            str(Path.cwd()),
        ]
    )
    assert rc == 0
    # go.mod with no go.sum → lockfile Missing finding emitted at T1 severity.
    findings = _findings(out)
    lock = [f for f in findings if f["control"] == sca.CONTROL_LOCKFILE]
    assert lock and lock[0]["severity"] == "High"


def test_main_default_plugin_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    # No --plugin-root: defaults to the repo two levels up from the script,
    # which is the real plugin root containing data/sca-practice-severity.yaml.
    rc = sca.main(["--repo-root", str(repo), "--output-dir", str(out)])
    assert rc == 0
