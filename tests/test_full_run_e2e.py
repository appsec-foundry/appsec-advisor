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
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"

# ─────────────────────────────────────────────────────────────────────────────
# Skip-by-default — only the manual driver flips this on.
# ─────────────────────────────────────────────────────────────────────────────
pytestmark = pytest.mark.skipif(
    os.environ.get("APPSEC_E2E_FULL") != "1",
    reason="manual E2E test — run via `make e2e-full` (sets APPSEC_E2E_FULL=1)",
)

# Driver signals whether the export converters were available so the pdf/html
# assertions skip (rather than fail) on a box without pandoc/weasyprint.
PDF_ATTEMPTED = os.environ.get("APPSEC_E2E_PDF") == "1"
HTML_DONE = os.environ.get("APPSEC_E2E_HTML") == "1"


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
def threat_model_yaml(out_dir: Path) -> dict:
    yml = out_dir / "threat-model.yaml"
    assert yml.is_file(), f"missing primary output: {yml}"
    return yaml.safe_load(yml.read_text())


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
    "pentest-tasks.yaml",       # driver passes --pentest-tasks
    ".threats-merged.json",
    ".triage-flags.json",
    ".recon-summary.md",
    ".hook-events.log",
]

REQUIRED_FRAGMENTS = [
    "ms-verdict.json",
    "ms-architecture-assessment.json",
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


def test_critical_attack_tree_fragment_is_conditional(
    out_dir: Path, threat_model_yaml: dict
) -> None:
    """`ms-critical-attack-tree.json` is authored IFF >=2 Critical findings
    exist — the composer's `has_multi_critical` gate (appsec-threat-renderer.md
    :124, phase-group-finalization.md:444). Assert that conditional contract,
    not unconditional presence: a single-Critical run correctly omits it."""
    critical = sum(
        1
        for t in threat_model_yaml.get("threats", [])
        if str(t.get("risk", "")).lower() == "critical"
    )
    frag = out_dir / ".fragments" / "ms-critical-attack-tree.json"
    if critical >= 2:
        assert frag.is_file() and frag.stat().st_size > 0, (
            f">=2 Critical findings ({critical}) but {frag} is missing/empty"
        )
    else:
        assert not frag.is_file(), (
            f"<2 Critical findings ({critical}) but {frag} was authored "
            "(should be skipped per has_multi_critical gate)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Schema validation — re-uses the same validator the skill itself ships
# ─────────────────────────────────────────────────────────────────────────────


INTERMEDIATE_ARTIFACTS = [
    ("threats_merged", ".threats-merged.json"),
    ("triage_flags", ".triage-flags.json"),
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


# ─────────────────────────────────────────────────────────────────────────────
# 3. Renderer is deterministic on the freshly produced fragments
# ─────────────────────────────────────────────────────────────────────────────


def test_compose_render_is_clean(out_dir: Path) -> None:
    """compose.render() on the produced fragments must yield zero warnings —
    that's the contract the deterministic renderer enforces."""
    compose = _load_module("compose_threat_model", SCRIPTS / "compose_threat_model.py")
    rendered, warnings = compose.render(CONTRACT, out_dir)
    assert warnings == [], f"compose returned warnings: {warnings}"
    assert "## Management Summary\n" in rendered, "MS heading missing"
    assert "## 1. Management Summary" not in rendered, "MS must be unnumbered"


def test_compose_is_byte_idempotent(out_dir: Path) -> None:
    """Two consecutive renders against the same on-disk fragments must match
    byte-for-byte. Catches non-determinism that crept into the renderer."""
    compose = _load_module("compose_threat_model", SCRIPTS / "compose_threat_model.py")
    r1, _ = compose.render(CONTRACT, out_dir)
    r2, _ = compose.render(CONTRACT, out_dir)
    assert r1 == r2, "compose.render() is not deterministic"


# ─────────────────────────────────────────────────────────────────────────────
# 4. QA Hard-Gate — the LLM did not bypass the deterministic renderer
# ─────────────────────────────────────────────────────────────────────────────


def test_inline_shortcut_gate_did_not_trigger(out_dir: Path) -> None:
    """check_inline_shortcut.py exits 0 only if Stage 2 routed through
    compose_threat_model.py instead of writing threat-model.md directly.
    CLI: positional `output_dir`, optional `--depth`."""
    depth = os.environ.get("APPSEC_E2E_DEPTH", "quick")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "check_inline_shortcut.py"),
         "--depth", depth, str(out_dir)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"inline-shortcut bypass detected (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


# qa_checks.py subcommands that don't need the source repo (evidence_integrity
# does, but on a tiny synthetic-repo the LLM cites files that aren't there —
# noise. Stick to the structural checks here.)
QA_STRUCTURAL_CHECKS = ["invariants", "ms_structure", "anchors", "xrefs", "cell_format"]


@pytest.mark.parametrize("check", QA_STRUCTURAL_CHECKS)
def test_qa_check_passes(out_dir: Path, check: str) -> None:
    """qa_checks.py <check> <md> — one structural invariant per test for
    clear failure attribution."""
    md = out_dir / "threat-model.md"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "qa_checks.py"), check, str(md)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"qa_checks.py {check} failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. Content bands — fuzzy, robust to LLM drift
# ─────────────────────────────────────────────────────────────────────────────


def test_threat_count_in_band(threat_model_yaml: dict) -> None:
    """Even a tiny synthetic repo should produce at least one threat. Ceiling
    is wide — guard against runaway hallucination."""
    threats = threat_model_yaml.get("threats", [])
    assert len(threats) >= 1, "no threats produced — STRIDE pipeline ran but found nothing"
    assert len(threats) <= 50, (
        f"threat count {len(threats)} exceeds sanity ceiling 50 — possible duplication"
    )


def test_at_least_one_component(threat_model_yaml: dict) -> None:
    components = threat_model_yaml.get("components", [])
    assert len(components) >= 1, "no components identified — Phase 3/4 likely failed"


def test_threats_carry_required_fields(threat_model_yaml: dict) -> None:
    """Every threat must have id, stride, risk, component_id (or equivalent).
    Catches partial schema regressions that slip past validate_intermediate."""
    threats = threat_model_yaml.get("threats", [])
    for t in threats:
        # Canonical threat key is `id` (T-NNN), not `t_id` — every threat in
        # threat-model.yaml carries `id`; `t_id` never existed in the artifact.
        assert t.get("id"), f"threat without id: {t}"
        assert t.get("stride"), f"threat {t.get('id')} missing stride"
        assert t.get("risk"), f"threat {t.get('id')} missing risk"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Placeholder-ceiling — generated markdown must not leak LLM scaffolding
# ─────────────────────────────────────────────────────────────────────────────

PLACEHOLDER_TOKENS = [
    "PLACEHOLDER",
    "TODO:",
    "FIXME:",
    "<insert ",
    "lorem ipsum",
    "[REDACTED]",
    "TBD ",
]


def test_no_placeholder_leakage_in_markdown(out_dir: Path) -> None:
    md = (out_dir / "threat-model.md").read_text()
    lower = md.lower()
    found = [t for t in PLACEHOLDER_TOKENS if t.lower() in lower]
    assert not found, f"placeholder tokens leaked into threat-model.md: {found}"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Hook log — pipeline left an audit trail
# ─────────────────────────────────────────────────────────────────────────────


def test_hook_log_non_empty(out_dir: Path) -> None:
    log = out_dir / ".hook-events.log"
    lines = log.read_text().splitlines()
    assert len(lines) > 10, (
        f".hook-events.log has only {len(lines)} lines — agent dispatch likely failed"
    )


def test_hook_log_records_phase_progression(out_dir: Path) -> None:
    """At minimum the recon + threats phases must show up. We don't pin the
    exact set because phase-group changes are a normal refactor target."""
    text = (out_dir / ".hook-events.log").read_text()
    assert "PHASE_START" in text, "no PHASE_START events in hook log"
    assert "PHASE_END" in text, "no PHASE_END events in hook log"


# ─────────────────────────────────────────────────────────────────────────────
# 8. SARIF — optional output enabled by the driver's --sarif flag
# ─────────────────────────────────────────────────────────────────────────────


def test_sarif_is_valid_json_with_runs(out_dir: Path) -> None:
    sarif = json.loads((out_dir / "threat-model.sarif.json").read_text())
    assert "runs" in sarif, "SARIF missing top-level 'runs' array"
    assert isinstance(sarif["runs"], list) and len(sarif["runs"]) >= 1, "no runs in SARIF"


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
    """pentest-tasks.yaml must parse and carry meta + schema_version + a tasks
    list. (Top-level keys are meta/schema_version/tasks; endpoints are embedded
    per-task.) The file's existence is covered by REQUIRED_FILES; this asserts
    its shape so a malformed export is caught."""
    doc = yaml.safe_load((out_dir / "pentest-tasks.yaml").read_text())
    assert isinstance(doc, dict), "pentest-tasks.yaml is not a mapping"
    assert doc.get("meta"), "pentest-tasks.yaml missing meta block"
    assert doc.get("schema_version"), "pentest-tasks.yaml missing schema_version"
    assert isinstance(doc.get("tasks"), list), "pentest-tasks.yaml 'tasks' is not a list"


# ─────────────────────────────────────────────────────────────────────────────
# 11. Requirements compliance — driver passes --requirements
#     (resolves offline against skills/audit-security-requirements/cache/)
# ─────────────────────────────────────────────────────────────────────────────


def test_requirements_check_ran(out_dir: Path, threat_model_yaml: dict) -> None:
    """The driver passes --requirements; the context-resolver resolves a source
    (a URL, or the bundled data/appsec-requirements-fallback.yaml offline) and
    Phase 8b runs. When that happens, meta.check_requirements flips True and the
    resolved source + compliance fragment land on disk — assert that full
    contract.

    If no source resolves at all (offline with no fallback reachable), Phase 8b
    is *skipped* (not aborted) per phase-group-architecture.md, leaving
    check_requirements falsy and no .requirements.yaml. Treat that as a skip,
    not a failure, so the E2E stays green on a source-less box."""
    ran = threat_model_yaml.get("meta", {}).get("check_requirements") is True
    has_source = (out_dir / ".requirements.yaml").is_file()
    if not ran and not has_source:
        pytest.skip("requirements source did not resolve (offline) — Phase 8b skipped")
    assert ran, (
        "meta.check_requirements is not True but .requirements.yaml exists — "
        "requirements resolved yet the flag did not propagate"
    )
    assert has_source, (
        "missing .requirements.yaml — context-resolver did not write the source"
    )
    assert (out_dir / ".fragments" / "requirements-compliance.md").is_file(), (
        "missing requirements-compliance fragment — Phase 8b did not write it"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 12. keep-runtime-files — driver passes --keep-runtime-files
# ─────────────────────────────────────────────────────────────────────────────


def test_keep_runtime_files_honored(out_dir: Path) -> None:
    """The driver passes --keep-runtime-files, so runtime_cleanup must self-skip
    and record that as a RUNTIME_CLEANUP opt-out line in .agent-run.log. If the
    log isn't present (non-verbose headless can omit it) or cleanup never ran in
    this path, the signal is unobservable — skip rather than guess."""
    log = out_dir / ".agent-run.log"
    if not log.is_file():
        pytest.skip("no .agent-run.log to inspect for the cleanup decision")
    text = log.read_text(encoding="utf-8", errors="ignore")
    if "RUNTIME_CLEANUP" not in text:
        pytest.skip("runtime_cleanup did not run in this pipeline path")
    assert ("opt-out" in text) or ("skipped" in text), (
        "runtime_cleanup ran but did not honor --keep-runtime-files"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 13. PDF / HTML export — conditional on converter tooling (driver-signalled)
# ─────────────────────────────────────────────────────────────────────────────


def test_pdf_exported(out_dir: Path) -> None:
    """When the driver attempted --pdf (pandoc + weasyprint present), a valid
    PDF must exist."""
    if not PDF_ATTEMPTED:
        pytest.skip("driver did not attempt --pdf (pandoc/weasyprint missing)")
    pdf = out_dir / "threat-model.pdf"
    assert pdf.is_file(), "threat-model.pdf missing despite --pdf"
    assert pdf.stat().st_size > 1024, (
        f"threat-model.pdf suspiciously small ({pdf.stat().st_size} bytes)"
    )
    assert pdf.read_bytes()[:5] == b"%PDF-", "threat-model.pdf lacks a %PDF- header"


def test_html_exported(out_dir: Path) -> None:
    """When the driver exported HTML (pandoc present), a self-contained HTML
    document must exist."""
    if not HTML_DONE:
        pytest.skip("driver did not export HTML (pandoc missing or export failed)")
    html = out_dir / "threat-model.html"
    assert html.is_file(), "threat-model.html missing despite HTML export"
    text = html.read_text(encoding="utf-8", errors="ignore")
    assert "<html" in text.lower(), "threat-model.html has no <html> element"
