from __future__ import annotations

import ast
import json
from pathlib import Path

import model.emit_sca_practice as sca
import pytest
import yaml


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _controls(output_dir: Path) -> dict[str, dict]:
    """Rows and the sub-controls of the grouped row, by name."""
    data = json.loads((output_dir / ".security-controls.json").read_text(encoding="utf-8"))
    rows = {row["control"]: row for row in data["security_controls"]}
    for row in data["security_controls"]:
        rows.update({sub["title"]: sub for sub in row.get("subcontrols") or []})
    return rows


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
    # No update tool configured: it may run outside the repository, so no rating and no meta-finding.
    assert controls[sca.CONTROL_UPDATES]["status"] == sca.NOT_EVIDENCED
    assert "effectiveness" not in controls[sca.CONTROL_UPDATES]
    assert controls[sca.CONTROL_LOCKFILE]["effectiveness"] == "Partial"
    findings = _findings(out)
    assert {f["control"] for f in findings} == {sca.CONTROL_SCANNING, sca.CONTROL_LOCKFILE}
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
    tree = ast.parse((Path.cwd() / "scripts" / "model/emit_sca_practice.py").read_text(encoding="utf-8"))
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
    assert eff == sca.NOT_EVIDENCED
    assert ev == []


def test_classify_sca_scanning_ci_without_tool_is_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / ".github" / "workflows" / "ci.yml", "steps:\n  - run: echo hi\n")
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == sca.NOT_EVIDENCED
    assert ev == []


def test_classify_sca_scanning_records_line_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / "package-lock.json", "{}\n")
    _write(repo / ".github" / "workflows" / "ci.yml", "steps:\n  - run: snyk test\n")
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Adequate"
    assert ev == [".github/workflows/ci.yml:2"]


# --- Executable-step detection: true scanner invocations are credited ------


def test_scanner_in_block_scalar_is_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(
        repo / ".github" / "workflows" / "ci.yml",
        "jobs:\n  audit:\n    steps:\n      - name: Audit\n        run: |\n          npm ci\n          npm audit\n",
    )
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Adequate"
    assert ev == [".github/workflows/ci.yml:7"]


def test_dependency_review_action_reference_is_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(
        repo / ".github" / "workflows" / "review.yml",
        "jobs:\n  review:\n    steps:\n      - uses: actions/dependency-review-action@v4\n",
    )
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Adequate"
    assert ev == [".github/workflows/review.yml:4"]


def test_gitlab_script_list_is_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / ".gitlab-ci.yml", "audit:\n  script:\n    - npm ci\n    - npm audit\n")
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Adequate"
    assert ev == [".gitlab-ci.yml:4"]


def test_jenkinsfile_shell_step_is_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / "Jenkinsfile", "pipeline {\n  stages {\n    // audit stage\n    sh 'npm audit'\n  }\n}\n")
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Adequate"
    assert ev == ["Jenkinsfile:4"]


# --- Executable-step detection: tool names in data are not evidence --------


def test_tool_names_inside_github_script_body_are_not_credited(tmp_path: Path) -> None:
    """A PR-spam scorer naming scanners in a regex does not run one."""
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(
        repo / ".github" / "workflows" / "pr-compliance.yml",
        "jobs:\n"
        "  triage:\n"
        "    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            const tools = /semgrep|snyk|trivy|grype|zap/i;\n"
        "            if (tools.test(title)) score += 25;\n",
    )
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == sca.NOT_EVIDENCED
    assert ev == []


def test_commented_out_scanner_is_not_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(
        repo / ".github" / "workflows" / "ci.yml",
        "jobs:\n  build:\n    steps:\n      - run: |\n          # npm audit is disabled for now\n          npm ci\n",
    )
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == sca.NOT_EVIDENCED
    assert ev == []


def test_scanner_name_in_step_label_is_not_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(
        repo / ".github" / "workflows" / "ci.yml",
        "jobs:\n  build:\n    steps:\n      - name: npm audit (tracked in BACKLOG-12)\n        run: npm ci\n",
    )
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == sca.NOT_EVIDENCED
    assert ev == []


def test_codeql_alone_is_not_credited_as_sca(tmp_path: Path) -> None:
    """CodeQL is code scanning; dependency scanning is a separate feature."""
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(
        repo / ".github" / "workflows" / "codeql.yml",
        "jobs:\n"
        "  analyze:\n"
        "    steps:\n"
        "      - uses: github/codeql-action/init@v3\n"
        "        with:\n"
        "          languages: javascript\n"
        "      - uses: github/codeql-action/analyze@v3\n",
    )
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == sca.NOT_EVIDENCED
    assert ev == []


def test_bare_grype_token_without_arguments_is_not_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / ".github" / "workflows" / "ci.yml", "steps:\n  - run: echo grype\n")
    eff, _ = sca.classify_sca_scanning(repo)
    assert eff == sca.NOT_EVIDENCED


def test_grype_invocation_is_credited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / ".github" / "workflows" / "ci.yml", "steps:\n  - run: grype dir:.\n")
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == "Adequate"
    assert ev == [".github/workflows/ci.yml:2"]


def test_codeql_plus_tool_name_regex_repo_is_missing(tmp_path: Path) -> None:
    """Both signals that produced false SCA evidence, in one repo."""
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}\n")
    _write(repo / "package-lock.json", "{}\n")
    _write(
        repo / ".github" / "workflows" / "codeql-analysis.yml",
        "jobs:\n  analyze:\n    steps:\n      - uses: github/codeql-action/init@v3\n",
    )
    _write(
        repo / ".github" / "workflows" / "pr-compliance.yml",
        "jobs:\n"
        "  triage:\n"
        "    steps:\n"
        "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        "            const t = /snyk|trivy|grype/i;\n",
    )
    eff, ev = sca.classify_sca_scanning(repo)
    assert eff == sca.NOT_EVIDENCED
    assert ev == []


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
    assert eff == sca.NOT_EVIDENCED
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
    # And running twice is idempotent (no duplicate rows).
    assert sca.run(repo, out, "T2", Path.cwd()) == 0
    data = json.loads((out / ".security-controls.json").read_text(encoding="utf-8"))
    names = [r["control"] for r in data["security_controls"]]
    assert sorted(names) == sorted(["Hand-authored control", sca.CONTROL_GROUP])


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


@pytest.mark.parametrize(
    "files, expected",
    [
        (
            {".gitignore": "node_modules\n/package-lock.json\n", ".npmrc": "package-lock=false\n"},
            [".gitignore:2", ".npmrc:1"],
        ),
        ({".gitignore": "dist\nyarn.lock\n"}, [".gitignore:2"]),
        ({".gitignore": "node_modules\n"}, []),
    ],
)
def test_a_missing_lockfile_names_what_excludes_it(tmp_path: Path, files, expected) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo / "package.json", '{"dependencies": {"express": "^4.18.0"}}\n')
    for rel, text in files.items():
        _write(repo / rel, text)
    effectiveness, evidence = sca.classify_lockfile_hygiene(repo)
    assert (effectiveness, evidence) == ("Missing", expected)
    text = sca._assessment_text(sca.CONTROL_LOCKFILE, effectiveness, evidence)
    assert all(ref in text for ref in expected) and ("Excluded by" in text) == bool(expected)


# ---------------------------------------------------------------------------
# Supply-chain sub-controls (data/supply-chain-controls.yaml)
# ---------------------------------------------------------------------------

PLUGIN = Path(__file__).resolve().parents[1]


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    for rel, text in files.items():
        _write(repo / rel, text)
    return repo


def _git(repo: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_every_control_table_reference_exists() -> None:
    table = sca._load_control_table(PLUGIN)
    checks = {c["id"] for c in yaml.safe_load((PLUGIN / "data/config-iac-checks.yaml").read_text())["checks"]}
    rules = yaml.safe_load((PLUGIN / "data/architecture-coverage-rules.yaml").read_text())
    rule_ids = {r["id"] for r in rules["hard_rules"] + rules["hypothesis_rules"]}
    catalog = {c["name"] for c in yaml.safe_load((PLUGIN / "data/architectural-controls.yaml").read_text())["controls"]}
    assert set(table) == {
        sca.CONTROL_SCANNING,
        sca.CONTROL_UPDATES,
        sca.CONTROL_LOCKFILE,
        sca.CONTROL_CI_INSTALL,
        sca.CONTROL_ACTION_PINNING,
        sca.CONTROL_BASE_IMAGE,
        sca.CONTROL_INSTALL_SCRIPTS,
        sca.CONTROL_SAST,
    }
    for row in table.values():
        assert set(row.get("linked_checks") or []) <= checks
        assert set(row.get("rule_ids") or []) <= rule_ids
        assert set(row.get("catalog_names") or []) <= catalog
        assert bool(row.get("markers")) == bool(row.get("process"))


@pytest.mark.parametrize(
    "files, expected",
    [
        ({".gitlab-ci.yml": "include:\n  - template: Auto-DevOps.gitlab-ci.yml\n"}, ("Adequate", [".gitlab-ci.yml:2"])),
        (
            {".gitlab-ci.yml": "include:\n  - template: Security/Dependency-Scanning.gitlab-ci.yml\n"},
            ("Adequate", [".gitlab-ci.yml:2"]),
        ),
        (
            {
                ".gitlab-ci.yml": "include:\n  - template: Auto-DevOps.gitlab-ci.yml\nvariables:\n  DEPENDENCY_SCANNING_DISABLED: 'true'\n"
            },
            (sca.NOT_EVIDENCED, []),
        ),
        ({".snyk": "version: v1.25.0\n"}, ("Adequate", [".snyk:1"])),
        ({"README.md": "We use snyk test in CI.\n"}, (sca.NOT_EVIDENCED, [])),
    ],
)
def test_sca_counts_templates_and_out_of_ci_markers_and_otherwise_is_not_evidenced(tmp_path, files, expected) -> None:
    assert sca.classify_sca_scanning(_repo(tmp_path, files)) == expected


@pytest.mark.parametrize(
    "workflow, expected",
    [
        ("steps:\n  - run: npm audit || true\n", "Weak"),
        ("steps:\n  - name: audit\n    run: npm audit\n    continue-on-error: true\n", "Weak"),
        (
            "steps:\n  - run: npm audit\n  - name: lint\n    run: npm run lint\n    continue-on-error: true\n",
            "Adequate",
        ),
    ],
)
def test_a_scanner_whose_failure_is_discarded_cannot_block(tmp_path, workflow, expected) -> None:
    repo = _repo(tmp_path, {".github/workflows/ci.yml": workflow, "package.json": "{}\n"})
    assert sca.classify_sca_scanning(repo)[0] == expected


@pytest.mark.parametrize(
    "files, expected",
    [
        (
            {
                ".github/workflows/codeql.yml": "steps:\n  - uses: github/codeql-action/init@v3\n  - uses: github/codeql-action/analyze@v3\n"
            },
            "Adequate",
        ),
        ({".github/workflows/codeql.yml": "steps:\n  - uses: github/codeql-action/init@v3\n"}, sca.NOT_EVIDENCED),
        ({".github/workflows/ci.yml": "steps:\n  - run: semgrep ci\n"}, "Adequate"),
        (
            {
                ".github/workflows/pr.yml": "steps:\n  - uses: actions/github-script@v7\n    with:\n      script: |\n        const tools = /semgrep|sonar|bandit/i;\n"
            },
            sca.NOT_EVIDENCED,
        ),
        ({".gitlab-ci.yml": "include:\n  - template: Security/SAST.gitlab-ci.yml\n"}, "Adequate"),
        (
            {
                ".gitlab-ci.yml": 'include:\n  - template: Auto-DevOps.gitlab-ci.yml\nvariables:\n  SAST_DISABLED: "true"\n'
            },
            sca.NOT_EVIDENCED,
        ),
        ({"sonar-project.properties": "sonar.projectKey=app\n"}, "Adequate"),
        ({".semgrep/rules.yml": "rules: []\n"}, "Adequate"),
    ],
)
def test_sast_is_credited_from_invocations_templates_or_markers(tmp_path, files, expected) -> None:
    assert sca.classify_sast(_repo(tmp_path, files))[0] == expected


@pytest.mark.parametrize(
    "files, expected",
    [
        ({".github/dependabot.yaml": "version: 2\nupdates: []\n", "package.json": "{}\n"}, "Adequate"),
        ({"package.json": '{\n  "name": "app",\n  "renovate": {"extends": ["config:base"]}\n}\n'}, "Adequate"),
        ({"package.json": '{\n  "renovate": {"enabled": false}\n}\n'}, sca.NOT_EVIDENCED),
        ({"package.json": "{}\n"}, sca.NOT_EVIDENCED),
    ],
)
def test_update_tooling_is_evidenced_by_its_config_only(tmp_path, files, expected) -> None:
    repo = _repo(tmp_path, files)
    assert sca.classify_auto_updates(repo, tmp_path)[0] == expected


def test_an_ignored_lockfile_on_disk_is_not_in_the_repository(tmp_path) -> None:
    repo = _repo(tmp_path, {"package.json": "{}\n", ".gitignore": "package-lock.json\n", "package-lock.json": "{}\n"})
    _git(repo, "init", "-q")
    _git(repo, "add", "package.json", ".gitignore")
    assert sca.classify_lockfile_hygiene(repo) == ("Missing", [".gitignore:1"])
    (repo / ".gitignore").write_text("node_modules\n")
    _git(repo, "add", "-A")
    assert sca.classify_lockfile_hygiene(repo) == ("Adequate", ["package-lock.json:1"])


@pytest.mark.parametrize(
    "steps, expected",
    [
        ("  - run: npm ci\n", ("Adequate", [".github/workflows/ci.yml:2"])),
        ("  - run: npm install\n", ("Missing", [".github/workflows/ci.yml:2"])),
        ("  - run: npm ci\n  - run: yarn add left-pad\n", ("Partial", [".github/workflows/ci.yml:3"])),
        ("  - run: npm install -g @scope/cli\n", (None, [])),
        ("  - name: npm install\n    run: make\n", (None, [])),
    ],
)
def test_ci_install_integrity_grades_every_install_step(tmp_path, steps, expected) -> None:
    repo = _repo(tmp_path, {".github/workflows/ci.yml": "steps:\n" + steps})
    assert sca.classify_ci_install(repo) == expected


@pytest.mark.parametrize(
    "files, expected",
    [
        ({".github/workflows/ci.yml": "steps:\n  - uses: vendor/tool@" + "b" * 40 + "\n"}, "Adequate"),
        ({".github/workflows/ci.yml": "steps:\n  - uses: vendor/tool@v4\n"}, "Missing"),
        ({".github/workflows/ci.yml": "steps:\n  - uses: ./local-action\n"}, None),
        ({".gitlab-ci.yml": "build:\n  image: registry.example.invalid/builder@sha256:" + "c" * 64 + "\n"}, "Adequate"),
        ({".gitlab-ci.yml": "build:\n  image:\n    name: registry.example.invalid/builder:2\n"}, "Missing"),
    ],
)
def test_action_pinning_covers_actions_and_ci_images(tmp_path, files, expected) -> None:
    assert sca.classify_action_pinning(_repo(tmp_path, files))[0] == expected


@pytest.mark.parametrize(
    "dockerfile, expected",
    [
        ("FROM python@sha256:" + "d" * 64 + "\n", ("Adequate", ["deploy/Containerfile:1"])),
        ("FROM python:3.12\n", ("Partial", ["deploy/Containerfile:1"])),
        ("FROM python\n", ("Missing", ["deploy/Containerfile:1"])),
        ("# FROM python\n", (None, [])),
    ],
)
def test_base_image_pinning_reads_every_stage(tmp_path, dockerfile, expected) -> None:
    assert sca.classify_base_image_pinning(_repo(tmp_path, {"deploy/Containerfile": dockerfile})) == expected


@pytest.mark.parametrize(
    "files, expected",
    [
        ({".github/workflows/ci.yml": "steps:\n  - run: curl -sL https://get.example.invalid | bash\n"}, "Weak"),
        ({"build/Dockerfile.tools": "RUN wget -qO- https://get.example.invalid | sh\n"}, "Weak"),
        (
            {"package.json": '{\n  "scripts": {"postinstall": "curl https://x.example.invalid/i.sh | sh"}\n}\n'},
            "Missing",
        ),
        ({"package.json": '{\n  "scripts": {"postinstall": "node build.js"}\n}\n'}, "Partial"),
        (
            {
                "package.json": '{\n  "scripts": {"postinstall": "node build.js"}\n}\n',
                ".npmrc": "ignore-scripts=true\n",
            },
            "Adequate",
        ),
        ({"package.json": '{\n  "scripts": {"prepare": "husky install"}\n}\n'}, "Adequate"),
        ({"README.md": "curl https://x.example.invalid | sh\n"}, None),
    ],
)
def test_install_scripts_grade_fetch_and_execute_and_hooks(tmp_path, files, expected) -> None:
    assert sca.classify_install_scripts(_repo(tmp_path, files))[0] == expected


def test_a_theme_the_model_already_rates_gets_the_links_instead_of_a_second_row(tmp_path) -> None:
    repo = _repo(tmp_path, {".github/workflows/ci.yml": "steps:\n  - uses: vendor/tool@v4\n  - run: npm ci\n"})
    out = tmp_path / "out"
    out.mkdir()
    rule_control = {
        "domain": "Supply Chain",
        "control": "Workflow pinning",
        "effectiveness": "Partial",
        "rule_id": "ARCH-SUPPLY-001",
    }
    (out / ".security-controls.json").write_text(json.dumps({"schema_version": 1, "security_controls": [rule_control]}))
    for _ in range(2):  # idempotent
        assert sca.run(repo, out, "T2", PLUGIN) == 0
    rows = json.loads((out / ".security-controls.json").read_text())["security_controls"]
    assert [r["control"] for r in rows] == ["Workflow pinning", sca.CONTROL_GROUP]
    assert rows[0]["linked_checks"] == ["IAC-011"] and rows[0]["effectiveness"] == "Partial"
    assert sca.CONTROL_ACTION_PINNING not in {s["title"] for s in rows[1]["subcontrols"]}


def test_not_evidenced_process_controls_neither_lower_the_row_nor_raise_meta_findings(tmp_path) -> None:
    repo = _repo(
        tmp_path,
        {".github/workflows/ci.yml": "steps:\n  - run: npm ci\n", "package.json": "{}\n", "package-lock.json": "{}\n"},
    )
    out = tmp_path / "out"
    out.mkdir()
    legacy = [{"domain": sca.DOMAIN, "control": name, "effectiveness": "Missing"} for name in sca.SCA_CONTROLS]
    (out / ".security-controls.json").write_text(json.dumps({"schema_version": 1, "security_controls": legacy}))
    assert sca.run(repo, out, "T1", PLUGIN) == 0
    (row,) = json.loads((out / ".security-controls.json").read_text())["security_controls"]
    subs = {s["title"]: s for s in row["subcontrols"]}
    for name in (sca.CONTROL_SCANNING, sca.CONTROL_UPDATES, sca.CONTROL_SAST):
        assert subs[name]["status"] == sca.NOT_EVIDENCED and "effectiveness" not in subs[name]
    assert row["effectiveness"] == "Adequate"
    assert _findings(out) == []
