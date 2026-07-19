from pathlib import Path

ROOT = Path(__file__).parent.parent
RUN_FULL = ROOT / "tests" / "e2e" / "run-full.sh"
RUN_REPAIR = ROOT / "tests" / "e2e" / "run-repair.sh"
RUN_EVAL = ROOT / "tests" / "e2e" / "run-eval.sh"
RUN_FIXTURE_SUITE = ROOT / "tests" / "e2e" / "run-fixture-suite.sh"
MAKEFILE = ROOT / "Makefile"


def test_full_driver_uses_clean_fixture_copy_and_explicit_full_mode() -> None:
    text = RUN_FULL.read_text(encoding="utf-8")
    pipeline = text[
        text.index('"$PLUGIN_ROOT/scripts/run-headless.sh"') : text.index(
            "ELAPSED=", text.index('"$PLUGIN_ROOT/scripts/run-headless.sh"')
        )
    ]
    assert 'WORK_REPO="$PLUGIN_ROOT/tests/fixtures/e2e/_last-repo"' in text
    assert 'rm -rf "$WORK_REPO/docs/security"' in text
    assert 'git -C "$WORK_REPO" init -q' in text
    assert 'git -C "$WORK_REPO" add -f .' in text
    assert 'commit -qm "E2E fixture baseline"' in text
    assert "--full" in pipeline
    assert '--requirements "$PLUGIN_ROOT/examples/appsec-requirements-example.yaml"' in pipeline
    assert "--no-qa" not in pipeline
    assert ".e2e-driver.json" in text


def test_depth_targets_cover_standard_qa_and_thorough_architect_review() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "./tests/e2e/run-full.sh --depth standard" in text
    assert "./tests/e2e/run-full.sh --depth thorough" in text
    assert "e2e-full-repair: e2e-full-standard" in text


def test_repair_driver_is_self_contained_and_fails_on_pipeline_error() -> None:
    text = RUN_REPAIR.read_text(encoding="utf-8")
    assert "/home/" not in text
    assert 'SEED="${APPSEC_E2E_REPAIR_SEED:-$PLUGIN_ROOT/tests/fixtures/e2e/_last-run}"' in text
    assert 'REPO="${APPSEC_E2E_REPAIR_REPO:-$PLUGIN_ROOT/tests/fixtures/e2e/_last-repo}"' in text
    assert 'if [ "$RUN_STATUS" -ne 0 ]; then' in text
    assert "control_subsection_coverage" in text


def test_oracle_is_outside_scanned_fixture() -> None:
    fixture = (ROOT / "tests" / "fixtures" / "e2e" / "synthetic-repo").resolve()
    oracle = (ROOT / "tests" / "fixtures" / "e2e" / "oracle" / "expected-signals.json").resolve()
    assert fixture not in oracle.parents


def test_semantic_eval_target_gates_high_and_critical_defects() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    script = RUN_EVAL.read_text(encoding="utf-8")
    assert "e2e-full-eval: e2e-full" in makefile
    assert "/appsec-advisor:eval-threat-model" in script
    assert "eval-results.json" in script
    assert 'counts.get("critical", 0)' in script
    assert 'counts.get("high", 0)' in script


def test_external_fixture_suite_covers_all_declared_languages() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    script = RUN_FIXTURE_SUITE.read_text(encoding="utf-8")
    assert "e2e-fixture-suite:" in makefile
    for fixture in (
        "spring-boot-threat-fixture",
        "python-threat-fixture",
        "rust-threat-fixture",
        "go-threat-fixture",
        "node-typescript-threat-fixture",
        "python-langchain-llm-threat-fixture",
        "aws-terraform-threat-fixture",
        "npm-supply-chain-threat-fixture",
        "fifty-service-threat-fixture",
    ):
        assert fixture in script
    assert "--clean-output" in script
