from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import actor_discovery_cache as adc


def _plugin(tmp_path: Path, version: str = "1.2.0") -> Path:
    root = tmp_path / "plugin"
    agent = root / "agents" / "appsec-actor-discoverer.md"
    agent.parent.mkdir(parents=True)
    agent.write_text(f"<!-- DISCOVERY_PROMPT_VERSION: {version} -->\nprompt\n", encoding="utf-8")
    return root


def test_compute_key_is_stable_and_changes_with_each_input(tmp_path: Path):
    output = tmp_path / "out"
    output.mkdir()
    plugin = _plugin(tmp_path)
    (output / ".recon-summary.md").write_text("recon-a", encoding="utf-8")
    (output / ".config-scan-findings.json").write_text('{"findings":[]}', encoding="utf-8")
    (output / ".actor-fingerprints.json").write_text(
        json.dumps({"actors_inputs_fingerprint": "actors-a"}),
        encoding="utf-8",
    )

    first = adc.compute_key(output, plugin)
    assert first == adc.compute_key(output, plugin)

    (output / ".recon-summary.md").write_text("recon-b", encoding="utf-8")
    assert adc.compute_key(output, plugin) != first


def test_compute_key_tolerates_missing_optional_inputs(tmp_path: Path):
    output = tmp_path / "out"
    output.mkdir()
    key = adc.compute_key(output, _plugin(tmp_path))
    assert len(key) == 64


def test_cache_status_requires_valid_mapping_and_exact_key(tmp_path: Path):
    discovery = tmp_path / ".actors-discovered.json"
    discovery.write_text(json.dumps({"discovery_cache_key": "abc"}), encoding="utf-8")
    assert adc.cache_status(discovery, "abc") == "hit"
    assert adc.cache_status(discovery, "def") == "miss"
    discovery.write_text("{bad", encoding="utf-8")
    assert adc.cache_status(discovery, "abc") == "miss"


def test_cli_compute_and_check(tmp_path: Path):
    output = tmp_path / "out"
    output.mkdir()
    plugin = _plugin(tmp_path)
    script = Path(adc.__file__)
    computed = subprocess.run(
        [
            sys.executable,
            str(script),
            "compute",
            "--output-dir",
            str(output),
            "--plugin-root",
            str(plugin),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    discovery = output / ".actors-discovered.json"
    discovery.write_text(json.dumps({"discovery_cache_key": computed}), encoding="utf-8")
    checked = subprocess.run(
        [
            sys.executable,
            str(script),
            "check",
            "--discovery-output",
            str(discovery),
            "--expected-key",
            computed,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert checked == "hit"


def test_write_empty_emits_schema_shape(tmp_path: Path):
    output = tmp_path / ".actors-discovered.json"
    adc.write_empty(output, "a" * 64, "Static actors remain authoritative.")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["discovery_cache_key"] == "a" * 64
    assert payload["proposed_additional"] == []
    assert payload["inputs_questioned"] == []
    assert payload["coverage_rationale"] == "Static actors remain authoritative."
    assert payload["generated_at"].endswith("Z")
