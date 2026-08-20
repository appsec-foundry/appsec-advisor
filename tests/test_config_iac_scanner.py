from __future__ import annotations

import json
from pathlib import Path

import config_iac_scanner as scanner
import pytest
import yaml


def _check(check_id: str, iac_type: str, file_pattern: str, expect: str, **extra) -> dict:
    value = {
        "id": check_id,
        "name": f"Check {check_id}",
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
