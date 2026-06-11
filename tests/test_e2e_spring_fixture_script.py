from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "e2e_spring_fixture.sh"
DOC = ROOT / "docs" / "e2e-spring-fixture.md"


def test_e2e_spring_fixture_script_exists_and_documents_defaults():
    text = SCRIPT.read_text()

    assert "spring-boot-threat-fixture" in text
    assert "appsec-advisor-fixtures" in text
    assert "appsec-advisor-tests" in text
    assert "APPSEC_SPRING_E2E_ROOT" in text
    assert "--fixture-root <path>" in text
    assert "<fixture-root>/oracles/spring-boot-threat-fixture" in text
    assert "<fixture-root>/repos/spring-boot-threat-fixture" in text
    assert "--depth <level>" in text
    assert "--clean-output" in text
    assert "verify_threat_model.py" in text
    assert "/home/mrohr/appsec-advisor-tests" not in text


def test_e2e_spring_fixture_runs_oracle_after_pipeline_only():
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


def test_e2e_spring_fixture_doc_records_oracle_separation():
    text = DOC.read_text()

    assert "outside the scanned repo" in text
    assert "spring-boot-threat-fixture" in text
    assert "verify_threat_model.py" in text
    assert "./scripts/e2e_spring_fixture.sh --clean-output" in text
    assert "--fixture-root ../appsec-advisor-fixtures" in text
    assert "../appsec-advisor-tests" in text
    assert "APPSEC_SPRING_E2E_ROOT" in text
    assert "/home/mrohr/appsec-advisor-tests" not in text
