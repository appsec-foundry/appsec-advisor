from __future__ import annotations

import ast
import json
from pathlib import Path

import emit_sca_practice as sca


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
