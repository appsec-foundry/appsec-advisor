"""Manual full-run E2E assertions for appsec-advisor.

Runs only when invoked via `make e2e-full` or `tests/e2e/run-full.sh`. Those
set `APPSEC_E2E_FULL=1` and `APPSEC_E2E_OUTPUT_DIR=<path>` before pytest is
invoked; otherwise every test in this file is skipped, so the standard
`pytest tests/` run is unaffected.

The driver pre-runs `scripts/run-headless.sh` against a fixed synthetic repo;
these assertions inspect the resulting `_last-run/` artifacts. We deliberately
avoid byte-equality (LLM output drifts) and check structural invariants only:

  * canonical output files exist
  * threat-model.yaml validates against its schema
  * compose.render() reproduces the markdown cleanly (zero warnings)
  * every Stage-2 fragment is on disk
  * qa_checks.py exits 0 across the full check set
  * the inline-shortcut Hard-Gate did not trigger
  * the report contains at least one threat and avoids placeholder leakage
  * the hook log records the expected sub-agent dispatches

If you tighten any band here, document why in the assertion message.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
ORACLE = REPO_ROOT / "tests" / "fixtures" / "e2e" / "oracle" / "expected-signals.json"
REQUIREMENTS_SOURCE = REPO_ROOT / "examples" / "appsec-requirements-example.yaml"

if str(REPO_ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tests"))
from test_sarif_validation import validate_sarif  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# Skip-by-default — only the manual driver flips this on.
# ─────────────────────────────────────────────────────────────────────────────
pytestmark = pytest.mark.skipif(
    os.environ.get("APPSEC_E2E_FULL") != "1",
    reason="manual E2E test — run via `make e2e-full` (sets APPSEC_E2E_FULL=1)",
)


def _output_dir() -> Path:
    raw = os.environ.get("APPSEC_E2E_OUTPUT_DIR")
    assert raw, "APPSEC_E2E_OUTPUT_DIR must be set by the driver"
    out = Path(raw)
    assert out.is_dir(), f"output dir does not exist: {out}"
    return out


@pytest.fixture(scope="module")
def out_dir() -> Path:
    return _output_dir()


@pytest.fixture(scope="module")
def driver_metadata(out_dir: Path) -> dict:
    path = out_dir / ".e2e-driver.json"
    assert path.is_file(), f"missing E2E driver metadata: {path}"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} must contain a JSON object"
    return data


@pytest.fixture(scope="module")
def target_repo(driver_metadata: dict) -> Path:
    raw = os.environ.get("APPSEC_E2E_TARGET_REPO") or driver_metadata.get("target_repo")
    assert raw, "target repo missing from APPSEC_E2E_TARGET_REPO and .e2e-driver.json"
    repo = Path(raw)
    assert repo.is_dir(), f"E2E target repo does not exist: {repo}"
    return repo


@pytest.fixture(scope="module")
def assessment_depth(driver_metadata: dict) -> str:
    depth = str(driver_metadata.get("assessment_depth") or os.environ.get("APPSEC_E2E_DEPTH") or "")
    assert depth in {"quick", "standard", "thorough"}, f"invalid/missing E2E assessment depth: {depth!r}"
    return depth


@pytest.fixture(scope="module")
def threat_model_yaml(out_dir: Path) -> dict:
    yml = out_dir / "threat-model.yaml"
    assert yml.is_file(), f"missing primary output: {yml}"
    data = yaml.safe_load(yml.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{yml} root must be a mapping"
    return data


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# ─────────────────────────────────────────────────────────────────────────────
# 1. Existence — every artifact a real user run produces
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_FILES = [
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",  # driver passes --sarif
    "pentest-tasks.yaml",  # driver passes --pentest-tasks
    ".threats-merged.json",
    ".triage-flags.json",
    ".recon-summary.md",
    ".agent-run.log",
    ".hook-events.log",
    ".skill-config.json",
    ".stride-dispatch-manifest.json",
    ".components.json",
    ".architecture-coverage.json",
    ".render-integrity.json",
    ".run-issues.json",
    ".qa-secret-scan.json",
    ".appsec-checkpoint",
    ".appsec-cache/baseline.json",
    ".e2e-driver.json",
]

REQUIRED_FRAGMENTS = [
    "ms-verdict.json",
    "attack-walkthroughs.md",
    "system-overview.md",
    "assets.md",
    "attack-surface.md",
    "architecture-diagrams.md",
    "security-architecture.md",
    "out-of-scope.md",
    # NOT unconditional (removed 2026-06-05):
    #   - ms-critical-attack-tree.json     → only authored when >=2 Critical
    #     findings (composer gate `has_multi_critical`; see appsec-threat-
    #     renderer.md:124, phase-group-finalization.md:444). Covered by the
    #     conditional test below.
    #   - operational-strengths-overrides.json → explicitly OPTIONAL
    #     (phase-group-finalization.md:443) — absent when no controls qualify.
]


@pytest.mark.parametrize("name", REQUIRED_FILES)
def test_required_output_file_exists(out_dir: Path, name: str) -> None:
    path = out_dir / name
    assert path.is_file(), f"missing required output file: {path}"
    assert path.stat().st_size > 0, f"output file is empty: {path}"


@pytest.mark.parametrize("name", REQUIRED_FRAGMENTS)
def test_required_fragment_exists(out_dir: Path, name: str) -> None:
    path = out_dir / ".fragments" / name
    assert path.is_file(), f"missing fragment: {path}"
    assert path.stat().st_size > 0, f"fragment is empty: {path}"


def test_critical_attack_tree_fragment_is_conditional(out_dir: Path, threat_model_yaml: dict) -> None:
    """`ms-critical-attack-tree.json` is authored IFF >=2 Critical findings
    exist — the composer's `has_multi_critical` gate (appsec-threat-renderer.md
    :124, phase-group-finalization.md:444). Assert that conditional contract,
    not unconditional presence: a single-Critical run correctly omits it."""
    critical = sum(1 for t in threat_model_yaml.get("threats", []) if str(t.get("risk", "")).lower() == "critical")
    frag = out_dir / ".fragments" / "ms-critical-attack-tree.json"
    if critical >= 2:
        assert frag.is_file() and frag.stat().st_size > 0, (
            f">=2 Critical findings ({critical}) but {frag} is missing/empty"
        )
    else:
        assert not frag.is_file(), (
            f"<2 Critical findings ({critical}) but {frag} was authored (should be skipped per has_multi_critical gate)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Schema validation — re-uses the same validator the skill itself ships
# ─────────────────────────────────────────────────────────────────────────────


INTERMEDIATE_ARTIFACTS = [
    ("threats_merged", ".threats-merged.json"),
    ("triage_flags", ".triage-flags.json"),
    ("threat_model_output", "threat-model.yaml"),
    ("pentest_tasks", "pentest-tasks.yaml"),
]


@pytest.mark.parametrize("subcommand,filename", INTERMEDIATE_ARTIFACTS)
def test_validate_intermediate_artifact(out_dir: Path, subcommand: str, filename: str) -> None:
    """validate_intermediate.py <kind> <file> — per-artifact schema check."""
    path = out_dir / filename
    assert path.is_file(), f"missing intermediate artifact: {path}"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "validate_intermediate.py"), subcommand, str(path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"validate_intermediate.py {subcommand} failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


@pytest.mark.parametrize(
    ("subcommand", "filename"),
    [
        ("config_scan_findings", ".config-scan-findings.json"),
        ("source_auth_findings", ".source-auth-findings.json"),
    ],
)
def test_validate_optional_intermediate_artifact(out_dir: Path, subcommand: str, filename: str) -> None:
    path = out_dir / filename
    if not path.is_file():
        pytest.skip(f"{filename} not produced for this fixture")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "parse_error" not in data, f"{filename} is an error stub: {data.get('parse_error')}"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "validate_intermediate.py"), subcommand, str(path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"{subcommand} rejected {path}:\n{result.stdout}\n{result.stderr}"


def test_every_dispatched_stride_artifact_is_complete_and_schema_valid(out_dir: Path) -> None:
    manifest = json.loads((out_dir / ".stride-dispatch-manifest.json").read_text(encoding="utf-8"))
    components = manifest.get("components") or []
    assert components, "STRIDE dispatch manifest contains no components"
    for component in components:
        cid = component.get("component_id")
        assert cid, f"dispatch manifest component has no component_id: {component}"
        path = out_dir / f".stride-{cid}.json"
        assert path.is_file(), f"missing STRIDE result for dispatched component {cid}: {path}"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "parse_error" not in data, f"STRIDE result for {cid} is an error stub: {data.get('parse_error')}"
        assert data.get("partial") is not True, f"STRIDE result for {cid} is marked partial"
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "validate_intermediate.py"), "stride", str(path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"invalid STRIDE result {path}:\n{result.stdout}\n{result.stderr}"


def test_pre_render_fragment_gate_passes_without_mutating_run(out_dir: Path, tmp_path: Path) -> None:
    copied = tmp_path / "fragment-gate"
    copied.mkdir()
    shutil.copytree(out_dir / ".fragments", copied / ".fragments")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "validate_fragment.py"), "pre-render-gate", str(copied), "--json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"pre-render fragment gate failed:\n{result.stdout}\n{result.stderr}"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Renderer is deterministic on the freshly produced fragments
# ─────────────────────────────────────────────────────────────────────────────


def test_compose_render_is_clean(out_dir: Path, tmp_path: Path) -> None:
    """compose.render() on the produced fragments must yield zero warnings —
    that's the contract the deterministic renderer enforces."""
    copied = tmp_path / "compose-clean"
    shutil.copytree(out_dir, copied)
    compose = _load_module("compose_threat_model", SCRIPTS / "compose_threat_model.py")
    rendered, warnings = compose.render(CONTRACT, copied)
    assert warnings == [], f"compose returned warnings: {warnings}"
    assert "## Management Summary\n" in rendered, "MS heading missing"
    assert "## 1. Management Summary" not in rendered, "MS must be unnumbered"


def test_compose_is_byte_idempotent(out_dir: Path, tmp_path: Path) -> None:
    """Two consecutive renders against the same on-disk fragments must match
    byte-for-byte. Catches non-determinism that crept into the renderer."""
    copied = tmp_path / "compose-idempotent"
    shutil.copytree(out_dir, copied)
    compose = _load_module("compose_threat_model", SCRIPTS / "compose_threat_model.py")
    r1, _ = compose.render(CONTRACT, copied)
    r2, _ = compose.render(CONTRACT, copied)
    assert r1 == r2, "compose.render() is not deterministic"


# ─────────────────────────────────────────────────────────────────────────────
# 4. QA Hard-Gate — the LLM did not bypass the deterministic renderer
# ─────────────────────────────────────────────────────────────────────────────


def test_inline_shortcut_gate_did_not_trigger(out_dir: Path, assessment_depth: str) -> None:
    """check_inline_shortcut.py exits 0 only if Stage 2 routed through
    compose_threat_model.py instead of writing threat-model.md directly.
    CLI: positional `output_dir`, optional `--depth`."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_inline_shortcut.py"), "--depth", assessment_depth, str(out_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"inline-shortcut bypass detected (exit {result.returncode}):\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_full_qa_battery_passes_and_is_idempotent(out_dir: Path, target_repo: Path, tmp_path: Path) -> None:
    """Run the same complete detector battery used by the pipeline.

    Work on a copy because ``qa_checks.py all`` owns several safe autofixes.
    A completed E2E run must already contain those fixes, so the copied final
    Markdown must remain byte-identical.
    """
    copied = tmp_path / "qa-all"
    shutil.copytree(out_dir, copied)
    md = copied / "threat-model.md"
    before = md.read_bytes()
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "qa_checks.py"), "all", str(md), str(target_repo)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"qa_checks.py all failed (exit {result.returncode}):\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert md.read_bytes() == before, "qa_checks.py all mutated the supposedly-final threat-model.md"


@pytest.mark.parametrize("phase", ["build", "render"])
def test_completeness_contract_passes(out_dir: Path, phase: str) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "assert_completeness.py"),
            str(out_dir),
            "--phase",
            phase,
            "--plugin-root",
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"completeness contract failed for {phase}:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_render_integrity_certificate_is_clean(out_dir: Path) -> None:
    integrity = json.loads((out_dir / ".render-integrity.json").read_text(encoding="utf-8"))
    assert integrity.get("report_integrity_ok") is True, integrity.get("broken_sections")
    assert integrity.get("integrity_pct") == 100, integrity
    assert integrity.get("sections_degraded") == 0, integrity.get("broken_sections")
    assert integrity.get("sections_empty") == 0, integrity.get("broken_sections")
    assert integrity.get("fragments_wired", 0) >= integrity.get("fragments_expected", 0) - 1, integrity


# ─────────────────────────────────────────────────────────────────────────────
# 5. Content bands — fuzzy, robust to LLM drift
# ─────────────────────────────────────────────────────────────────────────────


def test_threat_count_in_band(threat_model_yaml: dict) -> None:
    """Even a tiny synthetic repo should produce at least one threat. Ceiling
    is wide — guard against runaway hallucination."""
    threats = threat_model_yaml.get("threats", [])
    assert len(threats) >= 1, "no threats produced — STRIDE pipeline ran but found nothing"
    assert len(threats) <= 50, f"threat count {len(threats)} exceeds sanity ceiling 50 — possible duplication"


def test_at_least_one_component(threat_model_yaml: dict) -> None:
    components = threat_model_yaml.get("components", [])
    assert len(components) >= 1, "no components identified — Phase 3/4 likely failed"


def test_threats_carry_required_fields(threat_model_yaml: dict) -> None:
    """Every threat carries the user-facing identity/rating fields."""
    threats = threat_model_yaml.get("threats", [])
    for t in threats:
        # Canonical threat key is `id` (T-NNN), not `t_id` — every threat in
        # threat-model.yaml carries `id`; `t_id` never existed in the artifact.
        assert t.get("id"), f"threat without id: {t}"
        assert t.get("component"), f"threat {t.get('id')} missing component"
        assert t.get("stride"), f"threat {t.get('id')} missing stride"
        assert t.get("risk"), f"threat {t.get('id')} missing risk"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Placeholder-ceiling — generated markdown must not leak LLM scaffolding
# ─────────────────────────────────────────────────────────────────────────────

# Uppercase scaffolding markers — matched case-SENSITIVELY. Real LLM scaffolding
# is always emitted in caps (PLACEHOLDER, NARRATIVE_PLACEHOLDER, {{PLACEHOLDER}},
# [REDACTED]); the lowercase words are valid prose — e.g. "parameterized
# placeholders" is correct SQL terminology in a remediation and must NOT trip
# this gate (false positive observed in the 2026-06-27 E2E).
PLACEHOLDER_TOKENS = [
    "PLACEHOLDER",
    "TODO:",
    "FIXME:",
    "[REDACTED]",
    "TBD ",
]
# Filler prose whose capitalisation varies — matched case-INSENSITIVELY.
PLACEHOLDER_TOKENS_CI = [
    "<insert ",
    "lorem ipsum",
]


def test_no_placeholder_leakage_in_markdown(out_dir: Path) -> None:
    md = (out_dir / "threat-model.md").read_text()
    lower = md.lower()
    found = [t for t in PLACEHOLDER_TOKENS if t in md]
    found += [t for t in PLACEHOLDER_TOKENS_CI if t.lower() in lower]
    assert not found, f"placeholder tokens leaked into threat-model.md: {found}"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Hook log — pipeline left an audit trail
# ─────────────────────────────────────────────────────────────────────────────


def test_hook_log_non_empty(out_dir: Path) -> None:
    log = out_dir / ".hook-events.log"
    lines = log.read_text().splitlines()
    assert len(lines) > 10, f".hook-events.log has only {len(lines)} lines — agent dispatch likely failed"


def test_hook_log_records_phase_progression(out_dir: Path) -> None:
    """At minimum the recon + threats phases must show up. We don't pin the
    exact set because phase-group changes are a normal refactor target."""
    text = (out_dir / ".hook-events.log").read_text()
    assert "PHASE_START" in text, "no PHASE_START events in hook log"
    assert "PHASE_END" in text, "no PHASE_END events in hook log"


def _model_family(value: object) -> str:
    match = re.search(r"(haiku|sonnet|opus)", str(value or ""), re.IGNORECASE)
    return match.group(1).lower() if match else ""


def test_expected_agents_and_stride_dispatches_were_executed(
    out_dir: Path,
    assessment_depth: str,
) -> None:
    log = (out_dir / ".hook-events.log").read_text(encoding="utf-8", errors="ignore")
    for agent in (
        "appsec-context-resolver",
        "appsec-recon-scanner",
        "appsec-config-scanner",
        "appsec-threat-renderer",
    ):
        assert agent in log, f"hook log has no dispatch record for {agent}"

    manifest = json.loads((out_dir / ".stride-dispatch-manifest.json").read_text(encoding="utf-8"))
    expected_count = len(manifest.get("components") or [])
    stride_lines = [
        line for line in log.splitlines() if re.search(r"AGENT_(?:SPAWN|INVOKE).*appsec-stride-analyzer", line)
    ]
    assert len(stride_lines) >= expected_count, (
        f"only {len(stride_lines)} STRIDE analyzer dispatches recorded for {expected_count} manifest components"
    )

    config = json.loads((out_dir / ".skill-config.json").read_text(encoding="utf-8"))
    expected_model = _model_family(config.get("stride_model"))
    assert expected_model, f"cannot determine configured STRIDE model from {config.get('stride_model')!r}"
    observed: list[tuple[str, str]] = []
    for line in stride_lines:
        match = re.search(r"\bmodel=(\S+)", line)
        assert match, f"STRIDE dispatch line has no model field: {line}"
        observed.append((_model_family(match.group(1)), line))
    wrong = [line for family, line in observed if family != expected_model]
    assert not wrong, f"STRIDE dispatch model differs from resolved {expected_model}: " + "\n".join(wrong[:5])

    if assessment_depth != "quick":
        assert "appsec-actor-discoverer" in log, "non-quick run did not dispatch actor discovery"


def test_checkpoint_and_run_issues_show_clean_completion(out_dir: Path) -> None:
    checkpoint = (out_dir / ".appsec-checkpoint").read_text(encoding="utf-8")
    assert "phase=11" in checkpoint and "status=completed" in checkpoint, checkpoint

    issues = json.loads((out_dir / ".run-issues.json").read_text(encoding="utf-8"))
    assert issues.get("summary", {}).get("errors") == 0, issues
    categories = {str(issue.get("category")) for issue in issues.get("issues") or []}
    assert "stride_model_mismatch" not in categories, issues


# ─────────────────────────────────────────────────────────────────────────────
# 8. SARIF — optional output enabled by the driver's --sarif flag
# ─────────────────────────────────────────────────────────────────────────────


def test_sarif_is_schema_valid_and_has_no_silent_drops(out_dir: Path, threat_model_yaml: dict) -> None:
    sarif = json.loads((out_dir / "threat-model.sarif.json").read_text())
    valid, errors = validate_sarif(sarif)
    assert valid, f"SARIF validation failed: {errors}"

    exporter = _load_module("export_sarif_e2e", SCRIPTS / "export_sarif.py")
    expected = {
        threat.get("id")
        for threat in threat_model_yaml.get("threats") or []
        if threat.get("id") and exporter._is_sarif_exportable(threat)[0]
    }
    results = sarif["runs"][0].get("results") or []
    actual = [result.get("ruleId") for result in results]
    assert len(actual) == len(set(actual)), f"duplicate SARIF results: {actual}"
    assert set(actual) == expected, f"SARIF result IDs differ from exportable YAML threats: {set(actual) ^ expected}"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Meta echo — quick sanity that meta block has the run identity
# ─────────────────────────────────────────────────────────────────────────────


def test_meta_block_populated(threat_model_yaml: dict) -> None:
    meta = threat_model_yaml.get("meta", {})
    assert meta.get("schema_version"), "meta.schema_version missing"
    assert meta.get("generated"), "meta.generated missing"
    assert meta.get("plugin_version"), "meta.plugin_version missing"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Pentest tasks — driver passes --pentest-tasks
# ─────────────────────────────────────────────────────────────────────────────


def test_pentest_tasks_structure(out_dir: Path) -> None:
    """pentest-tasks.yaml must parse and carry meta (with schema_version) + a
    tasks list. (Top-level keys are meta/tasks/endpoints; schema_version lives
    under meta — see render_pentest_tasks.py:763 and the canonical
    test_pentest_tasks.py:187.) The file's existence is covered by REQUIRED_FILES;
    this asserts its shape so a malformed export is caught."""
    doc = yaml.safe_load((out_dir / "pentest-tasks.yaml").read_text())
    assert isinstance(doc, dict), "pentest-tasks.yaml is not a mapping"
    assert doc.get("meta"), "pentest-tasks.yaml missing meta block"
    assert doc.get("meta", {}).get("schema_version"), "pentest-tasks.yaml missing meta.schema_version"
    assert isinstance(doc.get("tasks"), list), "pentest-tasks.yaml 'tasks' is not a list"
    task_ids = [task.get("task_id") for task in doc["tasks"]]
    assert len(task_ids) == len(set(task_ids)), f"duplicate pentest task IDs: {task_ids}"
    threat_ids = {
        threat.get("id")
        for threat in yaml.safe_load((out_dir / "threat-model.yaml").read_text(encoding="utf-8")).get("threats", [])
    }
    for task in doc["tasks"]:
        if task.get("origin", {}).get("source") == "threat":
            assert task.get("threat_id") in threat_ids, f"pentest task references unknown threat: {task}"
        assert task.get("safety", {}).get("read_only") is True, f"pentest task is not read-only: {task}"
        assert task.get("safety", {}).get("destructive_actions") == "forbidden", task


# ─────────────────────────────────────────────────────────────────────────────
# 11. Requirements compliance — driver passes --requirements
#     (resolves offline against skills/audit-security-requirements/cache/)
# ─────────────────────────────────────────────────────────────────────────────


def test_requirements_check_ran(out_dir: Path, threat_model_yaml: dict, assessment_depth: str) -> None:
    """The driver passes --requirements; the context-resolver resolves a source
    (a URL, or the bundled data/appsec-requirements-fallback.yaml offline) and
    Phase 8b runs. When that happens, meta.check_requirements flips True and the
    resolved source + compliance fragment land on disk — assert that full
    contract.

    The driver supplies a local source explicitly. Missing requirements output
    (the 11 deterministic checks) is therefore a hard failure, not an
    environment-dependent skip. The ONE LLM-semantic check — at least one threat
    annotated with a provided requirement id — is depth-calibrated: hard at
    standard/thorough, advisory at quick (``--lenient``), where per-threat
    annotation is not reliably produced by the shallow run. Hard-gating a release
    on non-deterministic LLM output would make the gate flaky; the deterministic
    half stays strict at every depth."""
    ran = threat_model_yaml.get("meta", {}).get("check_requirements") is True
    has_source = (out_dir / ".requirements.yaml").is_file()
    assert ran, (
        "meta.check_requirements is not True but .requirements.yaml exists — "
        "requirements resolved yet the flag did not propagate"
    )
    assert has_source, "missing .requirements.yaml — context-resolver did not write the source"
    assert (out_dir / ".fragments" / "requirements-compliance.md").is_file(), (
        "missing requirements-compliance fragment — Phase 8b did not write it"
    )
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tests" / "e2e" / "verify_requirements_integration.py"),
        "--out",
        str(out_dir),
        "--source",
        str(REQUIREMENTS_SOURCE),
    ]
    if assessment_depth == "quick":
        cmd.append("--lenient")
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"requirements integration verification failed:\n{result.stdout}\n{result.stderr}"


# ─────────────────────────────────────────────────────────────────────────────
# 12. keep-runtime-files — driver passes --keep-runtime-files
# ─────────────────────────────────────────────────────────────────────────────


def test_keep_runtime_files_honored(out_dir: Path) -> None:
    """The driver passes --keep-runtime-files, so runtime_cleanup must self-skip
    and record that as a RUNTIME_CLEANUP opt-out line in .agent-run.log. If the
    Missing audit evidence is itself a failure in this developer E2E."""
    log = out_dir / ".agent-run.log"
    assert log.is_file(), f"missing audit log: {log}"
    text = log.read_text(encoding="utf-8", errors="ignore")
    assert "RUNTIME_CLEANUP" in text, "runtime cleanup decision was not logged"
    assert ("opt-out" in text) or ("skipped" in text), "runtime_cleanup ran but did not honor --keep-runtime-files"


def test_resolved_config_matches_driver_and_depth_contract(
    out_dir: Path,
    target_repo: Path,
    assessment_depth: str,
) -> None:
    config = json.loads((out_dir / ".skill-config.json").read_text(encoding="utf-8"))
    assert config.get("assessment_depth") == assessment_depth, config
    assert Path(config.get("repo_root", "")).resolve() == target_repo.resolve(), (
        f"resolved repo_root {config.get('repo_root')!r} != driver target {target_repo}"
    )
    assert config.get("mode") in {"full", "rebuild"}, config.get("mode")
    assert config.get("write_sarif") is True
    assert config.get("write_pentest_tasks") is True
    assert config.get("check_requirements") is True
    assert config.get("keep_runtime_files") is True

    if assessment_depth == "quick":
        assert config.get("skip_qa") is True
        assert config.get("skip_attack_walkthroughs") is True
        assert config.get("skip_attack_paths_authoring") is True
        assert config.get("enrich_arch_fragments") is False
    else:
        assert config.get("skip_qa") is False
        assert config.get("skip_attack_walkthroughs") is False
        assert config.get("skip_attack_paths_authoring") is False
        assert config.get("enrich_arch_fragments") is True
        qa_status = json.loads((out_dir / ".qa-status.json").read_text(encoding="utf-8"))
        assert qa_status.get("status") == "pass", qa_status
        assert (out_dir / ".actors-discovered.json").is_file(), "actor discovery output missing"
        assert (out_dir / ".actors-resolved.json").is_file(), "resolved actor catalog missing"
        resolved = json.loads((out_dir / ".actors-resolved.json").read_text(encoding="utf-8"))
        actors = resolved.get("resolved_actors") or []
        actor_ids = {actor.get("id") for actor in actors}
        assert "ACT-D-09" in actor_ids, "multi-tenancy actor was not activated"
        assert actor_ids & {"ACT-D-04", "ACT-D-06"}, "CI/secret signals activated no insider or supply-chain actor"
        discovered = json.loads((out_dir / ".actors-discovered.json").read_text(encoding="utf-8"))
        proposed_labels = {
            str(actor.get("label") or "").lower() for actor in discovered.get("proposed_additional") or []
        }
        assert any("partner" in label or "b2b" in label for label in proposed_labels), (
            f"B2B partner actor was not proposed: {sorted(proposed_labels)}"
        )
        assert (out_dir / ".fragments" / "security-posture-attack-paths.json").is_file(), (
            "non-quick run did not author the attack-path fragment"
        )

    if assessment_depth == "thorough":
        assert config.get("architect_review") is True
        review = out_dir / ".architect-review.md"
        assert review.is_file() and review.stat().st_size > 0, "Stage-4 architect review missing/empty"


def test_bundled_fixture_oracle_recall_and_secret_masking(
    out_dir: Path,
    target_repo: Path,
    driver_metadata: dict,
) -> None:
    if not driver_metadata.get("bundled_oracle"):
        pytest.skip("custom --repo run does not use the bundled fixture oracle")
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tests" / "e2e" / "verify_full_run_oracle.py"),
            "--out",
            str(out_dir),
            "--repo",
            str(target_repo),
            "--oracle",
            str(ORACLE),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"bundled fixture oracle failed:\n{result.stdout}\n{result.stderr}"


def test_bundled_fixture_deterministic_scanners_covered_planted_surfaces(
    out_dir: Path,
    driver_metadata: dict,
) -> None:
    if not driver_metadata.get("bundled_oracle"):
        pytest.skip("custom --repo run does not use bundled scanner expectations")
    for name in (".config-scan-findings.json", ".source-auth-findings.json", ".route-inventory.json"):
        path = out_dir / name
        assert path.is_file() and path.stat().st_size > 0, f"bundled fixture did not produce {name}"

    routes = json.loads((out_dir / ".route-inventory.json").read_text(encoding="utf-8")).get("routes") or []
    discovered = {(str(route.get("method")), str(route.get("path"))) for route in routes}
    expected = {
        ("POST", "/login"),
        ("GET", "/users/:id"),
        ("POST", "/admin/export"),
        ("POST", "/webhooks/preview"),
        ("POST", "/assistant"),
    }
    assert expected <= discovered, f"route inventory missed planted routes: {sorted(expected - discovered)}"


# ─────────────────────────────────────────────────────────────────────────────
# 13. PDF / HTML export — conditional on converter tooling (driver-signalled)
# ─────────────────────────────────────────────────────────────────────────────


def test_pdf_exported(out_dir: Path, driver_metadata: dict) -> None:
    """When the driver attempted --pdf (pandoc + weasyprint present), a valid
    PDF must exist."""
    if not driver_metadata.get("pdf_attempted"):
        pytest.skip("driver did not attempt --pdf (pandoc/weasyprint missing)")
    pdf = out_dir / "threat-model.pdf"
    assert pdf.is_file(), "threat-model.pdf missing despite --pdf"
    assert pdf.stat().st_size > 1024, f"threat-model.pdf suspiciously small ({pdf.stat().st_size} bytes)"
    assert pdf.read_bytes()[:5] == b"%PDF-", "threat-model.pdf lacks a %PDF- header"


def test_html_exported(out_dir: Path, driver_metadata: dict) -> None:
    """When the driver exported HTML (pandoc present), a self-contained HTML
    document must exist."""
    if not driver_metadata.get("html_attempted"):
        pytest.skip("driver did not attempt HTML export (pandoc missing)")
    assert driver_metadata.get("html_succeeded") is True, "HTML export was attempted but failed"
    html = out_dir / "threat-model.html"
    assert html.is_file(), "threat-model.html missing despite HTML export"
    text = html.read_text(encoding="utf-8", errors="ignore")
    assert "<html" in text.lower(), "threat-model.html has no <html> element"
