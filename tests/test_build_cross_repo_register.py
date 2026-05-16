"""Tests for ``scripts/build_cross_repo_register.py`` — unified cross-repo
register builder.

Covers:
  - merge precedence (declared > submodule > sibling > recon)
  - sibling discovery: TM found vs missing, cap at max_siblings
  - submodule discovery via .gitmodules
  - recon Section 7.25 parser (table + bullet style)
  - schema validation of the produced register
  - declared deduplication (a recon-discovered name that is already declared
    must not appear twice)
  - B0 skip — when ``--skip-sibling-discovery`` is passed, no sibling probe runs
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import build_cross_repo_register as bcrr  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "build_cross_repo_register.py"
SCHEMA = PLUGIN_ROOT / "schemas" / "cross-repo-register.schema.json"


def _make_repo(tmp_path: Path, name: str = "main-repo") -> Path:
    repo = tmp_path / "workspace" / name
    repo.mkdir(parents=True)
    return repo


def _make_sibling_with_tm(tmp_path: Path, name: str, generated: str = "2099-01-01T00:00:00Z") -> Path:
    sib = tmp_path / "workspace" / name
    (sib / "docs" / "security").mkdir(parents=True)
    (sib / "docs" / "security" / "threat-model.yaml").write_text(
        yaml.safe_dump(
            {
                "meta": {"generated": generated, "git": {"commit_sha": f"sha-{name}"}},
                "components": [{"name": "ComponentA"}],
                "threats": [
                    {"id": "T-1", "severity": "Critical", "status": "open"},
                    {"id": "T-2", "severity": "High", "status": "mitigated"},
                ],
            }
        )
    )
    return sib


def _make_sibling_without_tm(tmp_path: Path, name: str) -> Path:
    sib = tmp_path / "workspace" / name
    sib.mkdir(parents=True)
    return sib


# ---------------------------------------------------------------------------
# Sibling / submodule discovery
# ---------------------------------------------------------------------------


class TestSiblingDiscovery:
    def test_sibling_with_tm_is_found(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        _make_sibling_with_tm(tmp_path, "sib-a")
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        names = [e["name"] for e in reg["entries"]]
        assert "sib-a" in names
        sib_a = next(e for e in reg["entries"] if e["name"] == "sib-a")
        assert sib_a["source"] == "sibling"
        assert sib_a["threat_model"]["status"] == "found"
        assert sib_a["interface_findings"] is None  # never deep-read for siblings

    def test_sibling_without_tm_is_missing(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        _make_sibling_without_tm(tmp_path, "no-tm")
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        no_tm = next(e for e in reg["entries"] if e["name"] == "no-tm")
        assert no_tm["threat_model"]["status"] == "missing"

    def test_max_siblings_cap(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        for i in range(10):
            _make_sibling_without_tm(tmp_path, f"sib-{i:02d}")
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None, max_siblings=3)
        siblings = [e for e in reg["entries"] if e["source"] == "sibling"]
        assert len(siblings) == 3

    def test_skip_sibling_discovery(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        _make_sibling_with_tm(tmp_path, "sib-a")
        reg = bcrr.build(
            repo,
            declared_json_path=None,
            recon_summary_path=None,
            skip_sibling_discovery=True,
        )
        assert all(e["source"] != "sibling" for e in reg["entries"])
        assert reg["meta"]["skipped_sibling_discovery"] is True


class TestB0AutoSkip:
    """B0-skip — protects standalone single-repo scans from listing unrelated
    workspace directories as 'missing' upstreams. Without this guard, a user
    who clones one repo into ~/projects/myrepo would see every adjacent dir
    flagged as a missing upstream + CWE-1059 gap-threat."""

    def test_workspace_with_one_dir_skips(self, tmp_path: Path) -> None:
        # Only the repo itself in the workspace — no siblings.
        repo = tmp_path / "lonely-repo"
        repo.mkdir()
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        assert reg["meta"]["skipped_sibling_discovery"] is True
        assert reg["meta"]["skip_reason"] is not None
        assert all(e["source"] != "sibling" for e in reg["entries"])

    def test_workspace_with_two_or_more_dirs_runs_discovery(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, "main")
        _make_sibling_without_tm(tmp_path, "other-1")
        _make_sibling_without_tm(tmp_path, "other-2")
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        assert reg["meta"]["skipped_sibling_discovery"] is False
        sibs = [e for e in reg["entries"] if e["source"] == "sibling"]
        assert len(sibs) == 2

    def test_declared_present_disables_auto_skip(self, tmp_path: Path) -> None:
        # Even with one repo in workspace, declared-deps mean the user has
        # opted into cross-repo work — run sibling discovery so we can warn
        # about missing models for the declared ones.
        repo = tmp_path / "lonely-repo"
        repo.mkdir()
        declared = tmp_path / "declared.json"
        declared.write_text(
            json.dumps(
                {
                    "related": [
                        {
                            "name": "auth",
                            "source": "declared",
                            "interface": None,
                            "threat_model": {"status": "found"},
                            "interface_findings": None,
                        }
                    ]
                }
            )
        )
        reg = bcrr.build(repo, declared_json_path=declared, recon_summary_path=None)
        # No auto-skip — declared deps signalled the user wants cross-repo.
        assert reg["meta"]["skipped_sibling_discovery"] is False

    def test_gitmodules_present_disables_auto_skip(self, tmp_path: Path) -> None:
        repo = tmp_path / "lonely-repo"
        repo.mkdir()
        (repo / ".gitmodules").write_text('[submodule "x"]\n  path = vendor/x\n  url = https://e/x.git\n')
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        assert reg["meta"]["skipped_sibling_discovery"] is False

    def test_home_workspace_skips(self, tmp_path: Path, monkeypatch) -> None:
        # When the workspace IS $HOME, every clone goes there — we never
        # want to interpret arbitrary home-dir folders as upstreams.
        ws = tmp_path / "home"
        ws.mkdir()
        repo = ws / "myrepo"
        repo.mkdir()
        for name in ("dotfiles", "downloads", "scratch"):
            (ws / name).mkdir()
        monkeypatch.setenv("HOME", str(ws))
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        assert reg["meta"]["skipped_sibling_discovery"] is True
        assert "HOME" in (reg["meta"]["skip_reason"] or "")


class TestSubmoduleDiscovery:
    def test_submodule_with_tm(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        sub = repo / "vendor" / "auth"
        (sub / "docs" / "security").mkdir(parents=True)
        (sub / "docs" / "security" / "threat-model.yaml").write_text(
            yaml.safe_dump(
                {
                    "meta": {"generated": "2099-01-01T00:00:00Z"},
                    "threats": [],
                }
            )
        )
        (repo / ".gitmodules").write_text(
            textwrap.dedent("""
            [submodule "auth"]
                path = vendor/auth
                url = https://github.com/example/auth.git
        """).strip()
        )
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        auth = next(e for e in reg["entries"] if e["name"] == "auth")
        assert auth["source"] == "submodule"
        assert auth["threat_model"]["status"] == "found"

    def test_submodule_without_tm_is_missing(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        (repo / "vendor" / "ghost").mkdir(parents=True)
        (repo / ".gitmodules").write_text(
            textwrap.dedent("""
            [submodule "ghost"]
                path = vendor/ghost
                url = https://example/ghost.git
        """).strip()
        )
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        ghost = next(e for e in reg["entries"] if e["name"] == "ghost")
        assert ghost["threat_model"]["status"] == "missing"


# ---------------------------------------------------------------------------
# Declared merging + dedup
# ---------------------------------------------------------------------------


class TestDeclaredMerge:
    def test_declared_overrides_sibling_with_same_name(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        _make_sibling_with_tm(tmp_path, "auth-service")
        declared_json = tmp_path / "declared.json"
        declared_json.write_text(
            json.dumps(
                {
                    "related": [
                        {
                            "name": "auth-service",
                            "source": "declared",
                            "interface": "REST API",
                            "threat_model": {
                                "status": "found",
                                "path": "/abs/path/tm.yaml",
                                "generated": "2099-01-01T00:00:00Z",
                            },
                            "interface_findings": {
                                "included": 2,
                                "excluded_count": 0,
                                "findings": [
                                    {
                                        "id": "T-1",
                                        "title": "x",
                                        "severity": "Critical",
                                        "stride": "S",
                                        "cwe": "CWE-79",
                                        "component": "X",
                                        "status": "open",
                                        "evidence_file": None,
                                    },
                                ],
                            },
                        }
                    ],
                }
            )
        )
        reg = bcrr.build(repo, declared_json_path=declared_json, recon_summary_path=None)
        auth = [e for e in reg["entries"] if e["name"] == "auth-service"]
        assert len(auth) == 1
        assert auth[0]["source"] == "declared"
        assert auth[0]["interface"] == "REST API"

    def test_recon_only_entry_persists(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        recon = tmp_path / "recon.md"
        recon.write_text(
            textwrap.dedent("""
            ### 7.25 Cross-repo & SaaS dependencies

            | Name | Type | Source | Interface | Repo Hint | Confidence |
            |------|------|--------|-----------|-----------|------------|
            | Stripe | saas | package.json:12 | SDK | — | high |
            | notification-svc | scm-sibling | docker-compose.yml:5 | gRPC | ../notif | high |
        """).strip()
        )
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=recon)
        names = sorted(e["name"] for e in reg["entries"])
        assert "Stripe" in names
        assert "notification-svc" in names
        stripe = next(e for e in reg["entries"] if e["name"] == "Stripe")
        assert stripe["source"] == "recon"
        assert stripe["type"] == "saas"
        assert stripe["threat_model"]["status"] == "n/a"

    def test_declared_dedupes_recon_entry_with_same_name(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        declared_json = tmp_path / "declared.json"
        declared_json.write_text(
            json.dumps(
                {
                    "related": [
                        {
                            "name": "auth-service",
                            "source": "declared",
                            "interface": "REST API",
                            "threat_model": {"status": "found"},
                            "interface_findings": None,
                        }
                    ],
                }
            )
        )
        recon = tmp_path / "recon.md"
        recon.write_text(
            textwrap.dedent("""
            ### 7.25 Cross-repo & SaaS dependencies

            | Name | Type | Source | Interface | Repo Hint | Confidence |
            |------|------|--------|-----------|-----------|------------|
            | auth-service | scm-sibling | docker-compose.yml:5 | REST | ../auth | high |
        """).strip()
        )
        reg = bcrr.build(repo, declared_json_path=declared_json, recon_summary_path=recon)
        auth = [e for e in reg["entries"] if e["name"] == "auth-service"]
        assert len(auth) == 1
        assert auth[0]["source"] == "declared"


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_empty_register_validates(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        errors = bcrr._validate(reg, SCHEMA)
        assert errors == []

    def test_full_register_validates(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        _make_sibling_with_tm(tmp_path, "sib-a")
        recon = tmp_path / "recon.md"
        recon.write_text(
            textwrap.dedent("""
            ### 7.25 Cross-repo & SaaS dependencies

            | Name | Type | Source | Interface | Repo Hint | Confidence |
            |------|------|--------|-----------|-----------|------------|
            | Stripe | saas | package.json:12 | SDK | — | high |
        """).strip()
        )
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=recon)
        errors = bcrr._validate(reg, SCHEMA)
        assert errors == [], errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_writes_validated_output(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        out = tmp_path / "register.json"
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(repo), "--output", str(out)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["meta"]["register_version"] == 1
        assert isinstance(data["entries"], list)

    def test_cli_stdout(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path)
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(repo), "--output", "-"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(r.stdout)
        assert "entries" in data
