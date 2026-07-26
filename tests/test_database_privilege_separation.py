"""Regression tests for thorough-only database principal separation evidence."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "database_privilege_separation.py"
SKILL_IMPL = REPO_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
PHASE_RECON = REPO_ROOT / "agents" / "phases" / "phase-group-recon.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import database_privilege_separation as dbsep  # noqa: E402
import validate_intermediate as vi  # noqa: E402


def _run(repo: Path, output: Path, depth: str = "thorough") -> dict:
    subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo-root",
            str(repo),
            "--output-dir",
            str(output),
            "--assessment-depth",
            depth,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads((output / ".db-privilege-separation.json").read_text(encoding="utf-8"))


def test_confirms_only_visible_high_privilege_literal_grant_and_redacts_principal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "clients.ts").write_text(
        "const adminDb = createPool({ user: 'app_owner', password: 'not-for-output' });\n"
        "const publicDb = createPool({ user: 'app_owner', password: 'not-for-output' });\n",
        encoding="utf-8",
    )
    (repo / "roles.sql").write_text(
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_owner;\n",
        encoding="utf-8",
    )

    result = _run(repo, tmp_path / "out")
    assert len(result["confirmed_findings"]) == 1
    assert result["hypotheses"] == []
    record = result["confirmed_findings"][0]
    assert record["privileged_aliases"] == ["adminDb"]
    assert record["unprivileged_aliases"] == ["publicDb"]
    rendered = json.dumps(result)
    assert "app_owner" not in rendered
    assert "not-for-output" not in rendered
    ok, errors = vi.validate_db_privilege_separation(result)
    assert ok, errors


def test_shared_environment_reference_remains_hypothesis_when_grants_are_opaque(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "clients.ts").write_text(
        "const adminDb = createPool({ user: process.env.APP_DB_USER });\n"
        "const publicDb = createPool({ user: process.env.APP_DB_USER });\n",
        encoding="utf-8",
    )

    result = _run(repo, tmp_path / "out")
    assert result["confirmed_findings"] == []
    assert len(result["hypotheses"]) == 1
    assert result["hypotheses"][0]["principal_kind"] == "reference"
    assert "APP_DB_USER" not in json.dumps(result)


def test_distinct_clients_do_not_create_a_separation_record(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "clients.ts").write_text(
        "const adminDb = createPool({ user: 'admin_owner' });\n"
        "const publicDb = createPool({ user: 'application_user' });\n",
        encoding="utf-8",
    )
    result = _run(repo, tmp_path / "out")
    assert result["confirmed_findings"] == []
    assert result["hypotheses"] == []


def test_maps_generic_client_uses_in_admin_and_normal_route_contexts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src" / "admin").mkdir(parents=True)
    (repo / "src" / "routes").mkdir(parents=True)
    (repo / "src" / "db.ts").write_text(
        "const database = createPool({ user: 'app_owner' });\n",
        encoding="utf-8",
    )
    (repo / "src" / "admin" / "reports.ts").write_text(
        "export function reports() { return database.query('select 1'); }\n",
        encoding="utf-8",
    )
    (repo / "src" / "routes" / "orders.ts").write_text(
        "router.get('/orders', () => database.query('select 1'));\n",
        encoding="utf-8",
    )
    (repo / "roles.sql").write_text(
        "ALTER ROLE app_owner WITH BYPASSRLS;\n",
        encoding="utf-8",
    )

    result = _run(repo, tmp_path / "out")
    assert len(result["confirmed_findings"]) == 1
    record = result["confirmed_findings"][0]
    assert record["privileged_aliases"] == ["database"]
    assert record["unprivileged_aliases"] == ["database"]


def test_non_thorough_depth_is_a_no_scan_sidecar(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(dbsep, "_bindings", lambda _: (_ for _ in ()).throw(AssertionError("must not scan")))
    result = dbsep.assess(repo, "standard")
    assert result["skipped"] is True
    assert result["skip_reason"] == "database principal separation is assessed only at thorough depth"


def test_runtime_wiring_keeps_database_separation_thorough_only() -> None:
    for path in (SKILL_IMPL, PHASE_RECON):
        text = path.read_text(encoding="utf-8")
        assert "database_privilege_separation.py" in text
        assert '[ "$ASSESSMENT_DEPTH" = "thorough" ]' in text
    assert '--assessment-depth "$ASSESSMENT_DEPTH"' in SKILL_IMPL.read_text(encoding="utf-8")
