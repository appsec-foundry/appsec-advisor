"""Release contract for upgrading analysis baselines from v2 to v3."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import baseline_state
import compose_threat_model as compose
import plugin_meta
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_JSON = REPO_ROOT / ".claude-plugin" / "plugin.json"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
COMPOSE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "compose"


def test_analysis_v3_declares_v1_v2_read_compatibility() -> None:
    manifest = json.loads(PLUGIN_JSON.read_text(encoding="utf-8"))

    assert manifest["analysis_version"] == 3
    assert manifest["compatible_analysis_versions"] == [1, 2, 3]


def test_v2_baseline_recommends_full_without_hard_failure() -> None:
    manifest = json.loads(PLUGIN_JSON.read_text(encoding="utf-8"))
    meta = {
        "analysis_version": manifest["analysis_version"],
        "compatible_analysis_versions": manifest["compatible_analysis_versions"],
    }

    code, message = plugin_meta.classify_compat(2, meta)

    assert code == plugin_meta.EXIT_COMPAT_RECOMMEND_FULL
    assert "Incremental is still supported" in message
    assert "--full" in message


def test_v2_baseline_file_uses_upgrade_recommendation_path(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "output"
    shutil.copytree(COMPOSE_FIXTURE, output_dir)

    code = baseline_state.main(["check-compat", "--output-dir", str(output_dir)])

    assert code == plugin_meta.EXIT_COMPAT_RECOMMEND_FULL
    message = capsys.readouterr().err
    assert "source=threat-model.yaml" in message
    assert "baseline_version=2" in message


def test_v2_report_remains_renderable_and_is_not_rewritten(tmp_path: Path) -> None:
    output_dir = tmp_path / "output"
    shutil.copytree(COMPOSE_FIXTURE, output_dir)
    yaml_path = output_dir / "threat-model.yaml"
    before = yaml_path.read_bytes()
    yaml_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert yaml_data["meta"]["analysis_version"] == 2

    rendered, _warnings = compose.render(CONTRACT, output_dir)

    assert "## Management Summary" in rendered
    assert "analysis v3" in rendered
    assert yaml_path.read_bytes() == before
    integrity = json.loads((output_dir / ".render-integrity.json").read_text(encoding="utf-8"))
    assert integrity["schema_version"] == 1
    assert integrity["sections"]
