"""Standalone deterministic scanner selection, output, and failure tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "repo_scan.py"
sys.path.insert(0, str(ROOT / "scripts"))

import repo_scan as scan  # noqa: E402


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False)


@pytest.mark.parametrize("source_dir,route_name", [("src", "items"), ("service/api", "records")])
def test_endpoints_and_stack_can_be_selected_independently(tmp_path: Path, source_dir: str, route_name: str) -> None:
    folder = tmp_path / source_dir
    folder.mkdir(parents=True)
    (folder / "app.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        f"@router.get('/{route_name}')\ndef list_rows(): return []\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'neutral-example'\n", encoding="utf-8")

    endpoints = run("--repo", str(tmp_path), "--scan", "endpoints", "--yaml")
    assert endpoints.returncode == 0, endpoints.stderr
    payload = yaml.safe_load(endpoints.stdout)
    assert [scan["name"] for scan in payload["scans"]] == ["endpoints"]
    assert payload["summary"]["endpoints_total"] == 1
    assert "PROGRESS endpoints: enumerating" in endpoints.stderr
    assert "PROGRESS" not in endpoints.stdout
    assert ("GET", f"/{route_name}") in {(route["method"], route["path"]) for route in payload["scans"][0]["routes"]}

    stack = run("--repo", str(tmp_path), "--scan", "stack")
    assert stack.returncode == 0, stack.stderr
    assert "Python" in stack.stdout
    assert "fastapi" in stack.stdout
    assert f"/{route_name}" not in stack.stdout
    assert "SUMMARY scans=1 findings=0" in stack.stdout


@pytest.mark.parametrize("source_dir,route_name", [("src", "items"), ("service/api", "records")])
def test_json_stdout_matches_yaml_for_selected_scan(tmp_path: Path, source_dir: str, route_name: str) -> None:
    folder = tmp_path / source_dir
    folder.mkdir(parents=True)
    (folder / "app.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        f"@router.get('/{route_name}')\ndef list_rows(): return []\n",
        encoding="utf-8",
    )

    yaml_result = run("--repo", str(tmp_path), "--scan", "endpoints", "--yaml")
    json_result = run("--repo", str(tmp_path), "--scan", "endpoints", "--json")

    assert yaml_result.returncode == json_result.returncode == 0, json_result.stderr
    assert json.loads(json_result.stdout) == yaml.safe_load(yaml_result.stdout)
    assert json_result.stderr == ""
    assert "PROGRESS" not in json_result.stdout


def test_authz_only_runs_matching_checks_and_preserves_negative_case(tmp_path: Path) -> None:
    (tmp_path / "unsafe.ts").write_text(
        "export function read(req) {\n  return Orders.findAll({ where: { ownerId: req.body.ownerId } });\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "guarded.ts").write_text(
        "export function read(req) {\n"
        "  const rows = Orders.findAll({ where: { ownerId: req.body.ownerId } });\n"
        "  return requireOwnership(rows, req.user.id);\n}\n",
        encoding="utf-8",
    )
    result = run("--repo", str(tmp_path), "--scan", "authz", "--yaml")
    assert result.returncode == 0, result.stderr
    payload = yaml.safe_load(result.stdout)
    assert [scan["name"] for scan in payload["scans"]] == ["authz"]
    findings = payload["scans"][0]["findings"]
    assert any(row["check_id"] == "AUTHZ-001" and row["file"] == "unsafe.ts" for row in findings)
    assert all(row["file"] != "guarded.ts" for row in findings)
    assert all(row["check_id"].startswith("AUTHZ-") for row in findings)
    assert payload["summary"]["findings_total"] == len(findings)


def test_all_scans_and_yaml_file_leave_no_sidecars_in_target(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    output = tmp_path / "scan.yaml"
    result = run("--repo", str(repo), "--scan", "all", "--yaml", str(output))
    assert result.returncode == 0, result.stderr
    payload = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert {scan["name"] for scan in payload["scans"]} == {
        "config",
        "source",
        "mass-assignment",
        "architecture",
        "endpoints",
        "stack",
    }
    assert not list(repo.glob(".*findings.json"))
    assert not (repo / ".config-scan.json").exists()


def test_json_file_contains_validated_report_and_leaves_no_sidecars(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    output = tmp_path / "scan.json"

    result = run("--repo", str(repo), "--scan", "endpoints", "--json", str(output))

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["repo"] == str(repo)
    assert payload["scans"][0]["name"] == "endpoints"
    assert not list(repo.glob(".*findings.json"))


def test_json_and_yaml_are_mutually_exclusive_before_scanning(tmp_path: Path) -> None:
    result = run("--repo", str(tmp_path), "--json", "--yaml")

    assert result.returncode == 2
    assert "not allowed with argument" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("argument,exit_code", [("--help", 0), ("--unknown-option", 2)])
def test_help_and_unknown_options_exit_before_scanning(monkeypatch, capsys, argument: str, exit_code: int) -> None:
    monkeypatch.setattr(scan, "collect", lambda *args, **kwargs: pytest.fail("argument validation triggered a scan"))

    with pytest.raises(SystemExit) as exc:
        scan.main([argument])

    output = capsys.readouterr()
    assert exc.value.code == exit_code
    assert "usage:" in (output.out if exit_code == 0 else output.err)


def test_invalid_remote_url_fails_before_clone(tmp_path: Path) -> None:
    result = run("--repo", "https://user:pass@github.com/group/repo.git", "--scan", "stack")
    assert result.returncode == 1
    assert "credentials" in result.stderr


@pytest.mark.parametrize("url", ["https://github.com/team/example.git", "https://gitlab.com/team/example.git"])
def test_remote_urls_use_temporary_checkouts_without_network(url: str, monkeypatch, capsys) -> None:
    checkout_paths: list[Path] = []

    def fake_clone(_url: str, checkout: Path) -> None:
        checkout_paths.append(checkout)
        checkout.mkdir()
        (checkout / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n@app.get('/rows')\ndef rows(): return []\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(scan, "_clone", fake_clone)
    assert scan.main(["--repo", url, "--scan", "endpoints", "--yaml"]) == 0
    payload = yaml.safe_load(capsys.readouterr().out)
    assert payload["repo"] == url
    assert payload["scans"][0]["route_count"] == 1
    assert checkout_paths and not checkout_paths[0].exists()


def test_scanner_error_is_not_reported_as_a_clean_scan(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    result = run("--repo", str(missing), "--scan", "config")
    assert result.returncode == 1
    assert "not a directory" in result.stderr
    assert result.stdout == ""


def test_console_escapes_untrusted_route_controls() -> None:
    report = {
        "repo": "/tmp/repo",
        "scans": [
            {
                "name": "endpoints",
                "route_count": 1,
                "routes": [
                    {
                        "method": "GET",
                        "path": "/items\x1b[2J",
                        "framework": "express",
                        "handler_file": "app.js",
                        "handler_line": 2,
                    }
                ],
                "coverage": {},
            }
        ],
    }
    report["summary"] = scan.summarize(report["scans"])
    output = scan.render_text(report)
    assert "\\u001b" in output
    assert "\x1b" not in output


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ("all", {"Low", "Medium", "High", "Critical"}),
        ("medium", {"Medium", "High", "Critical"}),
        ("high", {"High", "Critical"}),
        ("critical", {"Critical"}),
    ],
)
def test_severity_thresholds_filter_findings_and_summary(tmp_path: Path, flag: str, expected: set[str]) -> None:
    data = {
        "checks_run": 4,
        "findings": [
            {"file": f"{severity.lower()}.py", "line": 1, "check_id": severity, "severity": severity}
            for severity in ("Low", "Medium", "High", "Critical")
        ],
    }
    result = scan._findings(data, "config", tmp_path, flag)
    assert {finding["severity"] for finding in result["findings"]} == expected
    summary = scan.summarize([result], flag)
    assert summary["findings_total"] == len(expected)
    assert summary["minimum_severity"] == flag
    assert sum(summary["severity_counts"].values()) == len(expected)


def test_cli_thresholds_are_exclusive_and_yaml_summary_matches_visible_findings(tmp_path: Path) -> None:
    (tmp_path / "unsafe.ts").write_text(
        "export function read(req) {\n  return Orders.findAll({ where: { ownerId: req.body.ownerId } });\n}\n",
        encoding="utf-8",
    )
    result = run("--repo", str(tmp_path), "--scan", "authz", "--critical", "--yaml")
    assert result.returncode == 0, result.stderr
    payload = yaml.safe_load(result.stdout)
    assert payload["summary"]["minimum_severity"] == "critical"
    assert payload["summary"]["findings_total"] == len(payload["scans"][0]["findings"])
    assert all(row["severity"].lower() == "critical" for row in payload["scans"][0]["findings"])
    assert "PROGRESS authz: scanning" in result.stderr
    assert run("--medium", "--high").returncode == 2


@pytest.mark.parametrize(
    ("source_dir", "route_name"),
    [("src", "items"), ("service/api", "records")],
)
def test_default_severity_filter_runs_finding_scans_without_routes(
    tmp_path: Path, source_dir: str, route_name: str
) -> None:
    folder = tmp_path / source_dir
    folder.mkdir(parents=True)
    (folder / "app.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        f"@router.get('/{route_name}')\ndef list_rows(): return []\n",
        encoding="utf-8",
    )

    result = run("--repo", str(tmp_path), "--critical", "--json")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert [entry["name"] for entry in payload["scans"]] == ["config", "source", "mass-assignment"]
    assert payload["summary"]["minimum_severity"] == "critical"
    assert payload["summary"]["endpoints_total"] is None
    assert result.stderr == ""


def test_explicit_endpoint_scan_still_runs_with_severity_filter(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/items')\ndef list_rows(): return []\n",
        encoding="utf-8",
    )

    result = run("--repo", str(tmp_path), "--scan", "endpoints", "--critical", "--json")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert [entry["name"] for entry in payload["scans"]] == ["endpoints"]
    assert payload["summary"]["endpoints_total"] == 1


def test_critical_text_report_omits_unselected_routes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/items')\ndef list_rows(): return []\n",
        encoding="utf-8",
    )

    result = run("--repo", str(tmp_path), "--critical")

    assert result.returncode == 0, result.stderr
    assert "minimum_severity=critical" in result.stdout
    assert "  endpoints:" not in result.stdout
    assert "  stack:" not in result.stdout
    assert "PROGRESS endpoints:" not in result.stderr


def test_summary_does_not_double_count_source_and_authz_overlap() -> None:
    finding = {"severity": "High", "file": "app.ts", "line": 2, "check_id": "AUTHZ-001"}
    unique_authz = {"severity": "Critical", "file": "other.ts", "line": 3, "check_id": "AUTHZ-002"}
    rows = [
        {"name": "source", "findings": [finding], "findings_total": 1},
        {"name": "authz", "findings": [finding, unique_authz], "findings_total": 2},
    ]
    summary = scan.summarize(rows)
    assert summary["scans_run"] == 2
    assert summary["findings_total"] == 2
    assert summary["severity_counts"]["high"] == 1
    assert summary["severity_counts"]["critical"] == 1
