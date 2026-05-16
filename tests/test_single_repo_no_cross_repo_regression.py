"""Regression tests for the single-repo scan path.

A user who runs ``/appsec-advisor:create-threat-model`` against a single
repository — without ``docs/related-repos.yaml``, without ``.gitmodules``,
without sibling repos with threat models — must NOT see any cross-repo
artifacts in the output. In particular, the deterministic helpers must:

  * load_related_repos.py            → empty result, no errors
  * build_cross_repo_register.py     → empty entries, ``skipped_sibling_discovery: true``
                                       when the workspace has 0/1 sibling dirs or is $HOME
  * slice_cross_repo_for_component   → ``[]``
  * coverage_checks.check_cross_repo → no missing_tm, no uncovered_boundaries,
                                       no CWE-1059 gap-threats
  * aggregate_threat_summary         → single-repo summary, no shared_cwes,
                                       no chain_candidates

These guarantees protect the most common use case from regressions caused
by future expansion of cross-repo discovery logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import aggregate_threat_summary as ats  # noqa: E402
import build_cross_repo_register as bcrr  # noqa: E402
import coverage_checks as cc  # noqa: E402
import load_related_repos as lrr  # noqa: E402
import slice_cross_repo_for_component as slicer  # noqa: E402


def _make_single_repo(tmp_path: Path, name: str = "myrepo") -> Path:
    """Simulate the typical 'one cloned repo, nothing else' workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repo = workspace / name
    (repo / "docs" / "security").mkdir(parents=True)
    return repo


class TestSingleRepoNoSpuriousArtifacts:
    def test_loader_returns_empty_on_clean_repo(self, tmp_path: Path) -> None:
        repo = _make_single_repo(tmp_path)
        result = lrr.load(repo)
        assert result["related"] == []
        assert result["errors"] == []

    def test_register_skips_sibling_discovery_on_single_repo(self, tmp_path: Path) -> None:
        repo = _make_single_repo(tmp_path)
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        assert reg["entries"] == []
        assert reg["meta"]["skipped_sibling_discovery"] is True

    def test_register_skips_when_workspace_is_home(self, tmp_path: Path, monkeypatch) -> None:
        # Simulate user cloning into $HOME with random other home-dir contents.
        ws = tmp_path / "fakehome"
        ws.mkdir()
        repo = ws / "myrepo"
        repo.mkdir()
        for name in ("downloads", "documents", "scratch", "vendor-dump"):
            (ws / name).mkdir()
        monkeypatch.setenv("HOME", str(ws))
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        assert reg["meta"]["skipped_sibling_discovery"] is True
        sibs = [e for e in reg["entries"] if e["source"] == "sibling"]
        assert sibs == []

    def test_slicer_returns_empty_with_empty_register(self, tmp_path: Path) -> None:
        repo = _make_single_repo(tmp_path)
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        sliced = slicer.slice_for_component(
            reg,
            component_name="App",
            interfaces=["HTTP /api/v1"],
            trust_boundaries=["client ↔ app"],
        )
        assert sliced == []

    def test_coverage_check_emits_no_cross_repo_gaps(self, tmp_path: Path) -> None:
        repo = _make_single_repo(tmp_path)
        out_dir = repo / "docs" / "security"
        # Build register (will be empty + skipped). Write it to OUTPUT_DIR.
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        (out_dir / ".cross-repo-register.json").write_text(json.dumps(reg))
        report = cc.check_cross_repo(
            out_dir / ".threat-modeling-context.md",
            threats=[{"t_id": "T-1", "title": "SQLi", "cwe": "CWE-89"}],
            register_path=out_dir / ".cross-repo-register.json",
        )
        assert report["register_used"] is True
        assert report["total_deps"] == 0
        assert report["missing_tm_count"] == 0
        assert report["uncovered_boundaries"] == []

    def test_run_all_no_spurious_cwe_1059(self, tmp_path: Path) -> None:
        """The single-repo flow must not produce CWE-1059 gap-threats just
        because unrelated workspace dirs lack threat models."""
        repo = _make_single_repo(tmp_path)
        out_dir = repo / "docs" / "security"
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        (out_dir / ".cross-repo-register.json").write_text(json.dumps(reg))
        (out_dir / ".threats-merged.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "threats": [{"t_id": "T-1", "cwe": "CWE-89"}],
                }
            )
        )
        report = cc.run_all(out_dir)
        cwe1059 = [
            b
            for b in report["cross_repo"].get("uncovered_boundaries", [])
            if b.get("suggested_threat", {}).get("cwe") == "CWE-1059"
        ]
        assert cwe1059 == [], f"unexpected CWE-1059 gap-threats: {cwe1059}"

    def test_aggregator_single_repo_has_no_shared_or_chain_artifacts(
        self,
        tmp_path: Path,
    ) -> None:
        repo = _make_single_repo(tmp_path)
        (repo / "docs" / "security" / "threat-model.yaml").write_text(
            yaml.safe_dump(
                {
                    "meta": {"generated": "2099-01-01T00:00:00Z", "git": {"commit_sha": "sha"}},
                    "components": [{"name": "App"}],
                    "threats": [
                        {
                            "id": "T-1",
                            "severity": "Critical",
                            "status": "open",
                            "cwe": "CWE-89",
                            "component": "App",
                            "stride": "Tampering",
                        },
                    ],
                }
            )
        )
        summary = ats.aggregate([repo], min_severity="medium", open_only=False)
        assert summary["shared_cwes"] == []
        assert summary["chain_candidates"] == []
        assert summary["shared_mitigations"] == []
        assert len(summary["consolidated_findings"]) == 1


class TestSingleRepoWithWorkspaceClutter:
    """Even with random adjacent directories — the classic ``~/projects``
    layout — the single-repo scan must not list them as upstreams."""

    def test_clutter_with_few_siblings_does_not_skip(self, tmp_path: Path) -> None:
        # >1 sibling without declared/.gitmodules → discovery runs, but every
        # adjacent dir is correctly reported as missing-TM (not silently
        # ignored) so the user sees what the heuristic found. This test
        # documents the contract — operators can then add the legitimate
        # ones to docs/related-repos.yaml.
        workspace = tmp_path / "projects"
        workspace.mkdir()
        repo = workspace / "myrepo"
        repo.mkdir()
        for n in ("notes", "scratch", "dotfiles", "vendor-dump"):
            (workspace / n).mkdir()
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        assert reg["meta"]["skipped_sibling_discovery"] is False
        sibs = [e for e in reg["entries"] if e["source"] == "sibling"]
        # All listed as missing — no spurious "found" entries.
        assert all(s["threat_model"]["status"] == "missing" for s in sibs)
        # Coverage check still produces CWE-1059 entries for these. That is
        # the documented behaviour — the heuristic flags any nearby repo as
        # a potential upstream-without-TM. The remedy is operator-visible:
        # either add to related-repos.yaml or accept the warning.
        # We verify the contract is consistent, not that the count is zero.
        assert len(sibs) >= 1

    def test_hidden_dirs_do_not_count_as_siblings(self, tmp_path: Path) -> None:
        # .git, .cache, .vscode etc. must not block B0-skip from kicking in.
        workspace = tmp_path / "projects"
        workspace.mkdir()
        repo = workspace / "myrepo"
        repo.mkdir()
        for n in (".cache", ".vscode", ".git"):
            (workspace / n).mkdir()
        reg = bcrr.build(repo, declared_json_path=None, recon_summary_path=None)
        # Only myrepo counts → 1 non-hidden dir → skip kicks in.
        assert reg["meta"]["skipped_sibling_discovery"] is True
