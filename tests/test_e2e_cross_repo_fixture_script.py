from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "e2e_cross_repo_fixture.sh"
DOC = ROOT / "docs" / "e2e-cross-repo-fixture.md"


def test_e2e_cross_repo_fixture_script_exists_and_documents_defaults():
    text = SCRIPT.read_text()

    assert "cross-repo-threat-fixture" in text
    assert "consumer-api" in text
    assert "auth-service" in text
    assert "payment-service" in text
    assert "appsec-advisor-fixtures" in text
    assert "APPSEC_CROSS_REPO_E2E_ROOT" in text
    assert "--fixture-root <path>" in text
    assert "<fixture-root>/oracles/cross-repo-threat-fixture" in text
    assert "<fixture-root>/repos/cross-repo-threat-fixture/consumer-api" in text
    assert "--depth <level>" in text
    assert "--clean-output" in text
    assert "docs/related-repos.yaml" in text
    assert "load_related_repos.py" in text
    assert "verify_threat_model.py" in text


def test_e2e_cross_repo_fixture_scans_consumer_only_and_runs_oracle_after_pipeline():
    text = SCRIPT.read_text()

    preflight_idx = text.index('python3 "$PLUGIN_ROOT/scripts/load_related_repos.py"')
    run_headless_idx = text.index('"$PLUGIN_ROOT/scripts/run-headless.sh" \\')
    verifier_idx = text.index('python3 "$ORACLE/verify_threat_model.py"')
    assert preflight_idx < run_headless_idx < verifier_idx

    pipeline_end_idx = text.index("ELAPSED=", run_headless_idx)
    pipeline_block = text[run_headless_idx:pipeline_end_idx]
    assert '--repo "$REPO"' in pipeline_block
    assert '--output "$OUTPUT"' in pipeline_block
    assert '--assessment-depth "$DEPTH"' in pipeline_block
    assert "--keep-runtime-files" in pipeline_block
    assert "ORACLE" not in pipeline_block
    assert "expected-signals.json" not in pipeline_block
    assert "auth-service" not in pipeline_block
    assert "payment-service" not in pipeline_block


def test_e2e_cross_repo_fixture_oracle_receives_output_dir():
    text = SCRIPT.read_text()

    verifier_idx = text.index('python3 "$ORACLE/verify_threat_model.py"')
    oracle_block = text[verifier_idx:]
    assert '--repo "$REPO"' in oracle_block
    assert '--report "$REPORT"' in oracle_block
    assert '--yaml "$YAML_REPORT"' in oracle_block
    assert '--output "$OUTPUT"' in oracle_block


def test_e2e_cross_repo_fixture_doc_records_manual_external_fixture_contract():
    text = DOC.read_text()

    assert "manual and opt-in" in text
    assert "does not run Claude Code" in text
    assert "outside the scanned repo" in text
    assert "consumer-api" in text
    assert "auth-service" in text
    assert "payment-service" in text
    assert "docs/related-repos.yaml" in text
    assert "docs/security/threat-model.yaml" in text
    assert "verify_threat_model.py" in text
    assert "./scripts/e2e_cross_repo_fixture.sh --clean-output" in text
    assert "--fixture-root ../appsec-advisor-fixtures" in text
    assert "APPSEC_CROSS_REPO_E2E_ROOT" in text
