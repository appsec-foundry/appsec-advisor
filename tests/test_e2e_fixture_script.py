from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "e2e_fixture.sh"
DOC = ROOT / "docs" / "internal" / "runbooks" / "e2e-fixtures.md"


def test_e2e_fixture_script_exists_and_documents_supported_fixtures():
    text = SCRIPT.read_text()

    for fixture in [
        "spring-boot-threat-fixture",
        "python-threat-fixture",
        "rust-threat-fixture",
        "go-threat-fixture",
        "node-typescript-threat-fixture",
        "python-langchain-llm-threat-fixture",
    ]:
        assert fixture in text

    assert "appsec-advisor-fixtures" in text
    assert "APPSEC_FIXTURE_E2E_ROOT" in text
    assert "APPSEC_FIXTURE_E2E_NAME" in text
    assert "--fixture <name>" in text
    assert "--list" in text
    assert "<fixture-root>/repos/<fixture>" in text
    assert "<fixture-root>/oracles/<fixture>" in text
    assert "<fixture-root>/outputs/<fixture>-e2e" in text
    assert "--depth <level>" in text
    assert "--clean-output" in text
    assert "verify_threat_model.py" in text


def test_e2e_fixture_runs_oracle_after_pipeline_only():
    text = SCRIPT.read_text()

    run_headless_idx = text.index('"$PLUGIN_ROOT/scripts/run-headless.sh" \\')
    verifier_idx = text.index('python3 "$ORACLE/verify_threat_model.py"')
    assert run_headless_idx < verifier_idx

    pipeline_end_idx = text.index("ELAPSED=", run_headless_idx)
    pipeline_block = text[run_headless_idx:pipeline_end_idx]
    assert '--repo "$REPO"' in pipeline_block
    assert '--output "$OUTPUT"' in pipeline_block
    assert '--assessment-depth "$DEPTH"' in pipeline_block
    assert "ORACLE" not in pipeline_block
    assert "expected-signals.json" not in pipeline_block


def test_e2e_fixture_doc_records_manual_external_fixture_contract():
    text = DOC.read_text()

    assert "manual and opt-in" in text
    assert "does not run Claude Code" in text
    assert "outside the scanned repo" in text
    assert "python-threat-fixture" in text
    assert "rust-threat-fixture" in text
    assert "go-threat-fixture" in text
    assert "node-typescript-threat-fixture" in text
    assert "python-langchain-llm-threat-fixture" in text
    assert "verify_threat_model.py" in text
    assert "./scripts/e2e_fixture.sh --fixture python-threat-fixture --depth quick --clean-output" in text
    assert "--fixture-root ../appsec-advisor-fixtures" in text
    assert "APPSEC_FIXTURE_E2E_ROOT" in text
