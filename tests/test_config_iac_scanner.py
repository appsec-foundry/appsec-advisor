from __future__ import annotations

import json
import subprocess
from pathlib import Path

import analyzers.config_iac_scanner as scanner
import pytest
import yaml


def _check(check_id: str, iac_type: str, file_pattern: str, expect: str, **extra) -> dict:
    value = {
        "id": check_id,
        "name": f"Check {check_id}",
        "violation_title": f"Violation {check_id}",
        "iac_type": iac_type,
        "file_pattern": file_pattern,
        "pattern": extra.pop("pattern", "secure"),
        "expect": expect,
        "severity_if_violated": "Medium",
        "cwe": "CWE-1000",
        "finding_type": "FT-100",
        "rationale": "The setting must satisfy policy.",
        "remediation": "Apply the secure setting",
    }
    value.update(extra)
    return value


def _catalog(tmp_path: Path, checks: list[dict], *, patterns_by_type: dict | None = None) -> Path:
    path = tmp_path / "checks.yaml"
    document = {"schema_version": 1, "checks": checks}
    if patterns_by_type is not None:
        document["file_patterns_by_type"] = patterns_by_type
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def test_scan_evaluates_catalog_and_emits_canonical_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM runtime:latest\nRUN install\n", encoding="utf-8")
    (repo / "package.json").write_text('{"scripts":{"postinstall":"setup"}}\n', encoding="utf-8")
    checks = [
        _check("IAC-001", "Dockerfile", "Dockerfile", "present", pattern=r"^USER "),
        _check("IAC-002", "Dockerfile", "Dockerfile", "absent", pattern="RUN install"),
        _check("IAC-003", "npm_config", "package.json", "absent_or_documented", pattern='"postinstall"'),
        _check("IAC-004", "npm_config", "package-lock.json", "file_exists", pattern=""),
    ]
    output = tmp_path / ".config-scan-findings.json"

    result = scanner.scan(repo, _catalog(tmp_path, checks), depth="standard", output=output)

    assert result["checks_run"] == 4
    assert result["violations"] == 4
    assert [row["local_id"] for row in result["findings"]] == ["CFG-001", "CFG-002", "CFG-003", "CFG-004"]
    assert [row["file"] for row in result["findings"]] == [
        "Dockerfile",
        "Dockerfile",
        "package.json",
        "package-lock.json",
    ]
    assert all(row["breach_vector"] == "Build-Time" for row in result["findings"])
    # The title names the defect; the desired-state `name` would read as a pass.
    assert [row["title"] for row in result["findings"]] == [check["violation_title"] for check in checks]
    assert all(row["scenario"].startswith(f"{row['title']}: ") for row in result["findings"])


@pytest.mark.parametrize("value", [None, "", "   "])
def test_catalog_rejects_a_check_without_a_violation_title(tmp_path, value):
    check = _check("IAC-001", "Dockerfile", "Dockerfile", "present")
    if value is None:
        del check["violation_title"]
    else:
        check["violation_title"] = value

    with pytest.raises(scanner.ConfigScanError):
        scanner._catalog(_catalog(tmp_path, [check]))


def test_quick_depth_scans_first_five_files_per_category(tmp_path):
    repo = tmp_path / "repo"
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for index in range(7):
        (workflows / f"{index}.yml").write_text("name: workflow\n", encoding="utf-8")
    checks = [_check("IAC-010", "github_workflow", ".github/workflows/*.yml", "present")]

    quick = scanner.scan(repo, _catalog(tmp_path, checks), depth="quick", output=tmp_path / "quick.json")
    standard = scanner.scan(repo, _catalog(tmp_path, checks), depth="standard", output=tmp_path / "standard.json")

    assert [row["file"] for row in quick["findings"]] == [f".github/workflows/{index}.yml" for index in range(5)]
    assert len(standard["findings"]) == 7


def test_category_patterns_cover_nested_and_yaml_alternatives(tmp_path):
    repo = tmp_path / "repo"
    workflows = repo / "service" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yaml").write_text("name: workflow\n", encoding="utf-8")
    checks = [_check("IAC-010", "github_workflow", ".github/workflows/*.yml", "present")]
    catalog = _catalog(
        tmp_path,
        checks,
        patterns_by_type={"github_workflow": ["**/.github/workflows/*.yml", "**/.github/workflows/*.yaml"]},
    )

    result = scanner.scan(repo, catalog, depth="standard", output=tmp_path / "result.json")

    assert [row["file"] for row in result["findings"]] == ["service/.github/workflows/ci.yaml"]


def test_shipped_catalog_scans_nested_compose_yaml(tmp_path):
    repo = tmp_path / "repo"
    service = repo / "services" / "api"
    service.mkdir(parents=True)
    (service / "compose.dev.yaml").write_text("services:\n  api:\n    privileged: true\n", encoding="utf-8")

    result = scanner.scan(repo, scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "result.json")

    shipped = yaml.safe_load(scanner.DEFAULT_CHECKS.read_text(encoding="utf-8"))["checks"]
    assert result["checks_run"] == len(shipped)
    assert any(
        row["check_id"] == "IAC-020" and row["file"] == "services/api/compose.dev.yaml" for row in result["findings"]
    )


def test_third_party_action_requires_full_sha_but_builtin_action_does_not(tmp_path):
    repo = tmp_path / "repo"
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "safe.yml").write_text("- uses: actions/checkout@v4\n", encoding="utf-8")
    (workflows / "unsafe.yml").write_text("- uses: vendor/tool@v2\n", encoding="utf-8")
    checks = [
        _check(
            "IAC-011",
            "github_workflow",
            ".github/workflows/*.yml",
            "all_third_party_actions",
            pattern=r"uses:\s+[^@]+@[0-9a-f]{40}",
        )
    ]

    result = scanner.scan(repo, _catalog(tmp_path, checks), depth="standard", output=tmp_path / "result.json")

    assert [row["file"] for row in result["findings"]] == [".github/workflows/unsafe.yml"]


def test_quoted_third_party_action_sha_is_accepted(tmp_path):
    repo = tmp_path / "repo"
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    revision = "a" * 40
    (workflows / "safe.yml").write_text(f"- uses : 'vendor/tool@{revision}'\n", encoding="utf-8")
    checks = [
        _check(
            "IAC-011",
            "github_workflow",
            ".github/workflows/*.yml",
            "all_third_party_actions",
        )
    ]

    result = scanner.scan(repo, _catalog(tmp_path, checks), depth="standard", output=tmp_path / "result.json")

    assert result["findings"] == []


def test_scan_rejects_symlink_escape(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.yml"
    outside.write_text("name: outside\n", encoding="utf-8")
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "linked.yml").symlink_to(outside)
    checks = [_check("IAC-010", "github_workflow", ".github/workflows/*.yml", "present")]

    with pytest.raises(scanner.ConfigScanError, match="escapes repository root"):
        scanner.scan(repo, _catalog(tmp_path, checks), depth="standard", output=tmp_path / "result.json")


@pytest.mark.parametrize("patterns", [[], [""], ["["]])
def test_scan_rejects_invalid_any_of_catalog_patterns(tmp_path, patterns):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "workflow.yml").write_text("name: test\n", encoding="utf-8")
    checks = [
        _check(
            "IAC-040",
            "github_workflow",
            "workflow.yml",
            "any_of_present",
            pattern_any_of=patterns,
        )
    ]

    with pytest.raises(scanner.ConfigScanError, match="pattern_any_of"):
        scanner.scan(repo, _catalog(tmp_path, checks), depth="standard", output=tmp_path / "result.json")


def test_main_writes_run_stable_timestamp(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / ".scan-start-epoch").write_text("0\n", encoding="utf-8")
    output = output_dir / ".config-scan-findings.json"
    checks = [_check("IAC-050", "npm_config", "package-lock.json", "file_exists", pattern="")]
    catalog = _catalog(tmp_path, checks)

    assert scanner.main(["--repo-root", str(repo), "--output", str(output), "--checks", str(catalog)]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["generated_at"] == "1970-01-01T00:00:00Z"


def _iac_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "deploy" / "k8s").mkdir(parents=True)
    (repo / "infra" / "prod").mkdir(parents=True)
    (repo / "docker-compose.yaml").write_text(
        "services:\n  db:\n    image: postgres\n    ports: ['5432:5432']\n"
        "    environment:\n      POSTGRES_PASSWORD: compose-literal-pw\n",
        encoding="utf-8",
    )
    (repo / "deploy" / "k8s" / "app.yml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: api}\nspec:\n  template:\n    spec:\n"
        "      containers:\n        - name: api\n          image: api\n"
        "          env: [{name: API_TOKEN, value: k8s-literal-token}]\n",
        encoding="utf-8",
    )
    (repo / "infra" / "prod" / "main.tf").write_text(
        'variable "db_password" {\n  default = "tf-literal-pw"\n}\n'
        'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n'
        '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        encoding="utf-8",
    )
    return repo


def test_shipped_catalog_covers_compose_kubernetes_and_terraform_and_masks_secrets(tmp_path):
    import validators.validate_intermediate as vi

    result = scanner.scan(_iac_repo(tmp_path), scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "r.json")

    hits = {(row["check_id"], row["file"]) for row in result["findings"]}
    assert {
        ("IAC-023", "docker-compose.yaml"),
        ("IAC-024", "docker-compose.yaml"),
        ("IAC-082", "deploy/k8s/app.yml"),
        ("IAC-083", "deploy/k8s/app.yml"),
        ("IAC-090", "infra/prod/main.tf"),
        ("IAC-093", "infra/prod/main.tf"),
    } <= hits
    breach = {row["check_id"]: row["breach_vector"] for row in result["findings"]}
    assert (
        breach["IAC-090"] == "Internet Anon" and breach["IAC-023"] == "Repo-Read" and breach["IAC-082"] == "Build-Time"
    )
    serialized = json.dumps(result)
    assert not any(value in serialized for value in ("compose-literal-pw", "k8s-literal-token", "tf-literal-pw"))
    assert "uncovered_iac" not in result
    assert vi.validate_config_scan_findings(result) == (True, [])


def test_recognised_surface_without_checks_is_reported_not_silent(tmp_path):
    import validators.validate_intermediate as vi

    repo = tmp_path / "repo"
    chart = repo / "charts" / "api"
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: api\n", encoding="utf-8")

    result = scanner.scan(repo, scanner.DEFAULT_CHECKS, depth="quick", output=tmp_path / "r.json")

    assert result["uncovered_iac"] == [{"iac_type": "helm", "file_count": 1, "files": ["charts/api/Chart.yaml"]}]
    assert vi.validate_config_scan_findings(result) == (True, [])


def test_repository_without_iac_reports_neither_findings_nor_uncovered_surfaces(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "config.yaml").write_text("password: not-iac\n", encoding="utf-8")

    result = scanner.scan(repo, scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "r.json")

    assert not [row for row in result["findings"] if row["iac_type"] in {"kubernetes", "terraform", "docker_compose"}]
    assert "uncovered_iac" not in result


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def git_home(tmp_path, monkeypatch):
    """Isolate git from the developer's global config; returns the global ignore file."""
    xdg = tmp_path / "xdg"
    (xdg / "git").mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    for key in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
        monkeypatch.setenv(key, "t")
    for key in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
        monkeypatch.setenv(key, "t@example.invalid")
    return xdg / "git" / "ignore"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _dockerfile_files(result: dict) -> list[str]:
    return sorted(row["file"] for row in result["findings"] if row["check_id"] == "IAC-901")


DOCKER_CHECK = _check("IAC-901", "Dockerfile", "**/Dockerfile", "absent", pattern="RUN install")


def test_scan_skips_files_git_ignores_and_keeps_untracked_repository_files(tmp_path, git_home):
    repo = tmp_path / "repo"
    for rel in ("Dockerfile", "new/Dockerfile", "ignored/Dockerfile", "personal/Dockerfile"):
        _write(repo / rel, "RUN install\n")
    _write(repo / ".gitignore", "ignored/\n")
    git_home.write_text("personal/\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "Dockerfile", ".gitignore")

    result = scanner.scan(repo, _catalog(tmp_path, [DOCKER_CHECK]), depth="standard", output=tmp_path / "r.json")

    assert result["inventory_source"] == "git"
    assert _dockerfile_files(result) == ["Dockerfile", "new/Dockerfile"]


def test_agent_config_checks_judge_only_tracked_settings(tmp_path, git_home):
    repo = tmp_path / "repo"
    _write(repo / ".claude" / "settings.json", '{"defaultMode": "bypassPermissions"}\n')
    _write(repo / ".claude" / "settings.local.json", '{"defaultMode": "bypassPermissions"}\n')
    _git(repo, "init", "-q")
    _git(repo, "add", ".claude/settings.json")
    check = _check("IAC-902", "agent_config", ".claude/settings*.json", "absent", pattern="bypassPermissions")

    result = scanner.scan(repo, _catalog(tmp_path, [check]), depth="standard", output=tmp_path / "r.json")

    assert [row["file"] for row in result["findings"]] == [".claude/settings.json"]


def test_scan_outside_git_walks_the_tree_and_says_so(tmp_path, capsys):
    repo = tmp_path / "repo"
    _write(repo / "svc" / "Dockerfile", "RUN install\n")
    catalog = _catalog(tmp_path, [DOCKER_CHECK])

    assert scanner.main(["--repo-root", str(repo), "--output", str(tmp_path / "r.json"), "--checks", str(catalog)]) == 0

    result = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert result["inventory_source"] == "filesystem-walk"
    assert _dockerfile_files(result) == ["svc/Dockerfile"]
    assert "inventory: filesystem-walk" in capsys.readouterr().out


def test_directory_an_enclosing_repository_ignores_is_walked_not_reported_empty(tmp_path, git_home):
    outer = tmp_path / "outer"
    _write(outer / ".gitignore", "scan/\n")
    _write(outer / "scan" / "Dockerfile", "RUN install\n")
    _git(outer, "init", "-q")

    result = scanner.scan(
        outer / "scan", _catalog(tmp_path, [DOCKER_CHECK]), depth="standard", output=tmp_path / "r.json"
    )

    assert result["inventory_source"] == "filesystem-walk"
    assert _dockerfile_files(result) == ["Dockerfile"]


def test_submodule_and_nested_repository_files_follow_their_own_ignore_rules(tmp_path, git_home):
    repo = tmp_path / "repo"
    inner = repo / "inner"
    _write(inner / "Dockerfile", "RUN install\n")
    _write(inner / "cache" / "Dockerfile", "RUN install\n")
    _write(inner / ".gitignore", "cache/\n")
    _git(inner, "init", "-q")
    _git(inner, "add", "Dockerfile", ".gitignore")
    _git(inner, "commit", "-q", "-m", "inner")
    nested = repo / "nested"
    _write(nested / "Dockerfile", "RUN install\n")
    _git(nested, "init", "-q")
    _git(repo, "init", "-q")
    head = subprocess.run(
        ["git", "-C", str(inner), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},inner")

    result = scanner.scan(repo, _catalog(tmp_path, [DOCKER_CHECK]), depth="standard", output=tmp_path / "r.json")

    assert _dockerfile_files(result) == ["inner/Dockerfile", "nested/Dockerfile"]


def test_catalog_rejects_an_unknown_breach_vector(tmp_path):
    catalog = _catalog(tmp_path, [_check("IAC-900", "Dockerfile", "Dockerfile", "absent", breach_vector="Nearby")])
    with pytest.raises(scanner.ConfigScanError, match="breach_vector"):
        scanner.scan(tmp_path, catalog, depth="standard", output=tmp_path / "r.json")
